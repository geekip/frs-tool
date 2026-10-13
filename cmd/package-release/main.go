package main

import (
	"flag"
	"fmt"
	"os"

	"frs-tool/internal/release"
)

func main() {
	version := flag.String("version", "", "release version")
	goos := flag.String("goos", "", "target GOOS")
	goarch := flag.String("goarch", "", "target GOARCH")
	binary := flag.String("binary", "", "compiled binary path")
	output := flag.String("out", "dist", "archive output directory")
	readme := flag.String("readme", "README.md", "public README path")
	config := flag.String("config", "config.example.json", "example config path")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	path, err := release.Create(release.Options{
		Version: *version, GOOS: *goos, GOARCH: *goarch, BinaryPath: *binary,
		ReadmePath: *readme, ConfigPath: *config, OutputDir: *output,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(path)
}
