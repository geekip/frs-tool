// Package release 创建元数据固定的发行归档。
package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

var archiveTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// Options 描述一个正式目标的归档输入。
type Options struct {
	Version    string
	GOOS       string
	GOARCH     string
	BinaryPath string
	ReadmePath string
	ConfigPath string
	OutputDir  string
}

type entry struct {
	name string
	mode os.FileMode
	data []byte
}

// Create 创建确定性 tar.gz 或 zip，并返回归档路径。
func Create(options Options) (string, error) {
	if err := validate(options); err != nil {
		return "", err
	}
	binary, err := os.ReadFile(options.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("read binary: %w", err)
	}
	readme, err := os.ReadFile(options.ReadmePath)
	if err != nil {
		return "", fmt.Errorf("read README: %w", err)
	}
	config, err := os.ReadFile(options.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("read example config: %w", err)
	}

	base := fmt.Sprintf("frs-%s-%s-%s", options.Version, options.GOOS, options.GOARCH)
	binaryName := "frs"
	suffix := ".tar.gz"
	if options.GOOS == "windows" {
		binaryName = "frs.exe"
		suffix = ".zip"
	}
	entries := []entry{
		{name: base + "/" + binaryName, mode: 0o755, data: binary},
		{name: base + "/README.md", mode: 0o644, data: readme},
		{name: base + "/config.example.json", mode: 0o644, data: config},
	}
	if err := os.MkdirAll(options.OutputDir, 0o755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	path := filepath.Join(options.OutputDir, base+suffix)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	writeErr := writeArchive(file, options.GOOS, entries)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return "", writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close archive: %w", closeErr)
	}
	return path, nil
}

func validate(options Options) error {
	if !versionPattern.MatchString(options.Version) {
		return errors.New("version must match vMAJOR.MINOR.PATCH")
	}
	validOS := options.GOOS == "linux" || options.GOOS == "darwin" || options.GOOS == "windows" || options.GOOS == "freebsd"
	if !validOS || options.GOARCH != "amd64" && options.GOARCH != "arm64" {
		return errors.New("unsupported release target")
	}
	if options.BinaryPath == "" || options.ReadmePath == "" || options.ConfigPath == "" || options.OutputDir == "" {
		return errors.New("archive paths must not be empty")
	}
	return nil
}

func writeArchive(writer io.Writer, goos string, entries []entry) error {
	if goos == "windows" {
		archive := zip.NewWriter(writer)
		for _, item := range entries {
			header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
			header.SetModTime(archiveTime)
			header.SetMode(item.mode)
			entryWriter, err := archive.CreateHeader(header)
			if err != nil {
				_ = archive.Close()
				return fmt.Errorf("create zip entry: %w", err)
			}
			if err := writeAll(entryWriter, item.data); err != nil {
				_ = archive.Close()
				return fmt.Errorf("write zip entry: %w", err)
			}
		}
		if err := archive.Close(); err != nil {
			return fmt.Errorf("close zip: %w", err)
		}
		return nil
	}

	compressed, err := gzip.NewWriterLevel(writer, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	compressed.Header.ModTime = archiveTime
	compressed.Header.OS = 255
	archive := tar.NewWriter(compressed)
	for _, item := range entries {
		header := &tar.Header{
			Name: item.name, Mode: int64(item.mode.Perm()), Size: int64(len(item.data)),
			ModTime: archiveTime, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := archive.WriteHeader(header); err != nil {
			_ = archive.Close()
			_ = compressed.Close()
			return fmt.Errorf("create tar entry: %w", err)
		}
		if err := writeAll(archive, item.data); err != nil {
			_ = archive.Close()
			_ = compressed.Close()
			return fmt.Errorf("write tar entry: %w", err)
		}
	}
	if err := archive.Close(); err != nil {
		_ = compressed.Close()
		return fmt.Errorf("close tar: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if count < 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
