//go:build cinterop && linux

package interop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"frs-tool/internal/extract"
	"frs-tool/internal/frs"
	"frs-tool/internal/index"
	"frs-tool/internal/merge"
	"frs-tool/internal/model"
	"frs-tool/internal/source"
)

func TestWriterMatchesIndependentCFixture(t *testing.T) {
	ftunSource, ftunBuild := ftunPaths(t)
	buildFTUN(t, ftunSource, ftunBuild)
	wantPath := filepath.Join(t.TempDir(), "c-fixture.frs")
	run(t, "", filepath.Join(ftunBuild, "ftun-v04-frs-test"), "--write", wantPath)
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frs.Verify(want); err != nil {
		t.Fatalf("strict Go verifier rejected independent C fixture: %v", err)
	}
	actual, err := frs.Encode(cFixtureSets(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("Go writer differs from independent C fixture\n got: %x\nwant: %x", actual, want)
	}
}

func TestGoWriterRealCLoaderQueryVectors(t *testing.T) {
	ftunSource, ftunBuild := ftunPaths(t)
	buildFTUN(t, ftunSource, ftunBuild)
	probe := compileProbe(t, ftunSource, ftunBuild)

	input, err := os.ReadFile("../../testdata/input/mixed-rules.txt")
	if err != nil {
		t.Fatal(err)
	}
	result := extract.New(extract.Config{MaxLineSize: 16 * 1024, MaxDiagnostics: 100}).Extract(
		context.Background(), source.MemoryRef(1, "mixed-rules.txt", input))
	if result.Status != extract.StatusSuccess {
		t.Fatalf("fixture extraction failed: %+v", result)
	}
	ip, err := index.BuildIPv4(result.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := index.BuildDomain(result.Domains)
	if err != nil {
		t.Fatal(err)
	}
	data, err := frs.Encode([]merge.Set{
		{Kind: merge.SetIPv4, Label: "mixed", IPv4: &ip},
		{Kind: merge.SetDomain, Label: "mixed", Domain: &domain},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frs.Verify(data); err != nil {
		t.Fatal(err)
	}
	frsPath := filepath.Join(t.TempDir(), "rules.frs")
	if err := os.WriteFile(frsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	var vectors []struct {
		Kind  string
		Value string
		Match bool
	}
	encoded, err := os.ReadFile("../../testdata/query-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.Kind+"/"+vector.Value, func(t *testing.T) {
			expected := "0"
			if vector.Match {
				expected = "1"
			}
			run(t, "", probe, frsPath, vector.Kind, "mixed", vector.Value, expected)
		})
	}
}

func ftunPaths(t *testing.T) (string, string) {
	t.Helper()
	sourceDir := os.Getenv("FTUN_SOURCE_DIR")
	if sourceDir == "" {
		t.Skip("FTUN_SOURCE_DIR is required for the explicit cinterop test")
	}
	sourceDir, err := filepath.Abs(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	buildDir := os.Getenv("FTUN_BUILD_DIR")
	if buildDir == "" {
		buildDir = filepath.Join(sourceDir, "build", "debug")
	}
	buildDir, err = filepath.Abs(buildDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "src", "frs", "frs.h")); err != nil {
		t.Fatalf("FTUN source tree is unavailable: %v", err)
	}
	return sourceDir, buildDir
}

func buildFTUN(t *testing.T, sourceDir, buildDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(buildDir, "CMakeCache.txt")); err != nil {
		run(t, "", "cmake", "-S", sourceDir, "-B", buildDir, "-DCMAKE_BUILD_TYPE=Debug")
	}
	run(t, "", "cmake", "--build", buildDir, "--target", "ftun_core", "ftun-v04-frs-test", "-j2")
}

func compileProbe(t *testing.T, sourceDir, buildDir string) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "frs-probe")
	libraries := []string{
		filepath.Join(buildDir, "libftun_core.a"),
		filepath.Join(buildDir, "libftun_cjson.a"),
		filepath.Join(buildDir, "libftun_libev.a"),
		filepath.Join(buildDir, "third_party", "wolfssl", "libwolfssl.a"),
		filepath.Join(buildDir, "libftun_lwip.a"),
	}
	for _, library := range libraries {
		if _, err := os.Stat(library); err != nil {
			t.Fatalf("required FTUN link artifact %s is unavailable: %v", library, err)
		}
	}
	arguments := []string{
		"-std=c11", "-Wall", "-Wextra", "-Werror",
		"-I", filepath.Join(sourceDir, "include"),
		"-I", filepath.Join(sourceDir, "src"),
		"testdata/frs_probe.c", "-Wl,--start-group",
	}
	arguments = append(arguments, libraries...)
	arguments = append(arguments, "-Wl,--end-group", "-lm", "-pthread", "-o", output)
	run(t, "", "cc", arguments...)
	return output
}

func run(t *testing.T, directory, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, arguments, err, output)
	}
}

func cFixtureSets(t testing.TB) []merge.Set {
	t.Helper()
	ip := index.IPv4Index{Ranges: []index.IPv4Range{
		{Lo: 0x0a000000, Hi: 0x0affffff},
		{Lo: 0xc0000200, Hi: 0xc00002ff},
	}, PrefixCount: 2}
	domain, err := index.BuildDomain([]model.Record{
		{Kind: model.RuleDomainExact, Value: "example.com"},
		{Kind: model.RuleDomainSuffix, Value: "example.org"},
		{Kind: model.RuleDomainKeyword, Value: "ads"},
	})
	if err != nil {
		t.Fatal(err)
	}
	unicode, err := index.BuildDomain([]model.Record{{Kind: model.RuleDomainKeyword, Value: "track"}})
	if err != nil {
		t.Fatal(err)
	}
	emptyIP := index.IPv4Index{}
	emptyDomain := index.DomainIndex{}
	return []merge.Set{
		{Kind: merge.SetIPv4, Label: "CN", IPv4: &ip},
		{Kind: merge.SetIPv4, Label: "empty", IPv4: &emptyIP},
		{Kind: merge.SetDomain, Label: "CN", Domain: &domain},
		{Kind: merge.SetDomain, Label: "empty", Domain: &emptyDomain},
		{Kind: merge.SetDomain, Label: "关键词🚀", Domain: &unicode},
	}
}
