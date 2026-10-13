package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCreateDeterministicArchives(t *testing.T) {
	for _, target := range []struct {
		goos, goarch string
	}{
		{goos: "linux", goarch: "amd64"},
		{goos: "windows", goarch: "arm64"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			input := t.TempDir()
			binary := filepath.Join(input, "binary")
			readme := filepath.Join(input, "README.md")
			config := filepath.Join(input, "config.json")
			mustWriteRelease(t, binary, []byte("binary"))
			mustWriteRelease(t, readme, []byte("readme\n"))
			mustWriteRelease(t, config, []byte("{}\n"))
			options := Options{Version: "v1.0.0", GOOS: target.goos, GOARCH: target.goarch, BinaryPath: binary, ReadmePath: readme, ConfigPath: config}
			options.OutputDir = filepath.Join(t.TempDir(), "one")
			first, err := Create(options)
			if err != nil {
				t.Fatal(err)
			}
			options.OutputDir = filepath.Join(t.TempDir(), "two")
			second, err := Create(options)
			if err != nil {
				t.Fatal(err)
			}
			firstData, _ := os.ReadFile(first)
			secondData, _ := os.ReadFile(second)
			if !bytes.Equal(firstData, secondData) {
				t.Fatal("archive bytes are not reproducible")
			}
			wantBinary := "frs"
			if target.goos == "windows" {
				wantBinary = "frs.exe"
			}
			want := []string{
				"frs-v1.0.0-" + target.goos + "-" + target.goarch + "/" + wantBinary,
				"frs-v1.0.0-" + target.goos + "-" + target.goarch + "/README.md",
				"frs-v1.0.0-" + target.goos + "-" + target.goarch + "/config.example.json",
			}
			if got := archiveNames(t, first, target.goos); !reflect.DeepEqual(got, want) {
				t.Fatalf("entries=%v want=%v", got, want)
			}
		})
	}
}

func TestCreateRejectsInvalidTargetAndVersion(t *testing.T) {
	for _, options := range []Options{
		{Version: "1.0.0", GOOS: "linux", GOARCH: "amd64"},
		{Version: "v1.0.0", GOOS: "plan9", GOARCH: "amd64"},
		{Version: "v1.0.0", GOOS: "linux", GOARCH: "386"},
	} {
		if _, err := Create(options); err == nil {
			t.Fatalf("accepted %+v", options)
		}
	}
}

func archiveNames(t *testing.T, path, goos string) []string {
	t.Helper()
	if goos == "windows" {
		archive, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		names := make([]string, len(archive.File))
		for index, file := range archive.File {
			names[index] = file.Name
		}
		return names
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	var names []string
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	return names
}

func mustWriteRelease(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
