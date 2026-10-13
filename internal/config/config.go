package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultDownloadConcurrency = 10
	DefaultPerHostConcurrency  = 3
	DefaultDownloadTimeout     = 120 * time.Second
	DefaultConnectTimeout      = 10 * time.Second
	DefaultRetries             = 3
	DefaultExtractConcurrency  = 5
	DefaultMaxLineSize         = int64(16 * 1024)
	DefaultMaxDiagnostics      = 1000
)

// Error 是带稳定代码和字段位置的配置错误。
type Error struct {
	Code  string
	Field string
	Err   error
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Field, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// ErrorCode 返回配置错误的稳定代码。
func ErrorCode(err error) string {
	var configError *Error
	if errors.As(err, &configError) {
		return configError.Code
	}
	return ""
}

type Config struct {
	ManifestPath string
	BaseDir      string
	Output       string
	IPv6         bool
	Download     DownloadConfig
	Extract      ExtractConfig
	Build        BuildConfig
	Groups       []Group
}

type DownloadConfig struct {
	Concurrency        int
	PerHostConcurrency int
	Timeout            time.Duration
	ConnectTimeout     time.Duration
	Retries            int
	Proxy              ProxyConfig
}

type ProxyConfig struct {
	Enabled bool
	URL     *url.URL
}

type ExtractConfig struct {
	Concurrency int
}

type BuildConfig struct {
	MaxLineSize    int64
	MaxDiagnostics int
}

type Group struct {
	Name    string
	Sources []string
}

type manifest struct {
	Output   *string           `json:"output"`
	IPv6     bool              `json:"ipv6"`
	Download *downloadManifest `json:"download"`
	Extract  *extractManifest  `json:"extract"`
	Build    *buildManifest    `json:"build"`
	Groups   []groupManifest   `json:"groups"`
}

type downloadManifest struct {
	Concurrency        *int           `json:"concurrency"`
	PerHostConcurrency *int           `json:"per-host-concurrency"`
	Timeout            *string        `json:"timeout"`
	ConnectTimeout     *string        `json:"connect-timeout"`
	Retries            *int           `json:"retries"`
	Proxy              *proxyManifest `json:"proxy"`
}

type proxyManifest struct {
	Enable bool    `json:"enable"`
	URL    *string `json:"url"`
}

type extractManifest struct {
	Concurrency *int `json:"concurrency"`
}

type buildManifest struct {
	MaxLineSize    *string `json:"max-line-size"`
	MaxDiagnostics *int    `json:"max-diagnostics"`
}

type groupManifest struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

// Load 读取并严格校验 JSON manifest。
func Load(path string) (Config, error) {
	manifestPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, configErr("CONFIG_PATH", "manifest", err)
	}
	manifestPath, err = filepath.EvalSymlinks(manifestPath)
	if err != nil {
		return Config{}, configErr("CONFIG_READ", "manifest", err)
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return Config{}, configErr("CONFIG_READ", "manifest", err)
	}
	data, err = prepareJSON(data)
	if err != nil {
		return Config{}, err
	}
	if err := validateJSON(data); err != nil {
		return Config{}, err
	}
	if err := validateExactKeys(data); err != nil {
		return Config{}, err
	}

	var raw manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, configErr("CONFIG_SCHEMA", "", err)
	}

	baseDir := filepath.Dir(manifestPath)
	cfg := Config{
		ManifestPath: manifestPath,
		BaseDir:      baseDir,
		IPv6:         raw.IPv6,
		Output:       filepath.Join(baseDir, "rules.frs"),
		Download: DownloadConfig{
			Concurrency:        DefaultDownloadConcurrency,
			PerHostConcurrency: DefaultPerHostConcurrency,
			Timeout:            DefaultDownloadTimeout,
			ConnectTimeout:     DefaultConnectTimeout,
			Retries:            DefaultRetries,
		},
		Extract: ExtractConfig{Concurrency: DefaultExtractConcurrency},
		Build: BuildConfig{
			MaxLineSize:    DefaultMaxLineSize,
			MaxDiagnostics: DefaultMaxDiagnostics,
		},
	}

	if raw.Output != nil {
		output := trimFixedWhiteSpace(*raw.Output)
		if output == "" {
			return Config{}, configErr("CONFIG_VALUE", "output", errors.New("must not be empty"))
		}
		if filepath.IsAbs(output) {
			cfg.Output = filepath.Clean(output)
		} else {
			cfg.Output = filepath.Join(baseDir, output)
		}
	}
	if cfg.IPv6 {
		return Config{}, configErr("CONFIG_UNSUPPORTED", "ipv6", errors.New("IPv6 output is not supported"))
	}
	if err := applyDownload(&cfg, raw.Download); err != nil {
		return Config{}, err
	}
	if err := applyExtract(&cfg, raw.Extract); err != nil {
		return Config{}, err
	}
	if err := applyBuild(&cfg, raw.Build); err != nil {
		return Config{}, err
	}
	if len(raw.Groups) == 0 {
		return Config{}, configErr("CONFIG_VALUE", "groups", errors.New("must contain at least one group"))
	}

	seen := make(map[string]struct{}, len(raw.Groups))
	cfg.Groups = make([]Group, 0, len(raw.Groups))
	for i, group := range raw.Groups {
		field := "groups[" + strconv.Itoa(i) + "]"
		if err := validateGroupName(group.Name); err != nil {
			return Config{}, configErr("CONFIG_GROUP_NAME", field+".name", err)
		}
		name := trimFixedWhiteSpace(group.Name)
		if name == "" {
			return Config{}, configErr("CONFIG_GROUP_NAME", field+".name", errors.New("must not be empty"))
		}
		if _, ok := seen[name]; ok {
			return Config{}, configErr("CONFIG_GROUP_NAME", field+".name", errors.New("duplicate group name"))
		}
		seen[name] = struct{}{}
		if len(group.Sources) == 0 {
			return Config{}, configErr("CONFIG_VALUE", field+".sources", errors.New("must not be empty"))
		}
		sources := make([]string, len(group.Sources))
		for sourceIndex, source := range group.Sources {
			source = trimFixedWhiteSpace(source)
			if source == "" {
				sourceField := field + ".sources[" + strconv.Itoa(sourceIndex) + "]"
				return Config{}, configErr("CONFIG_VALUE", sourceField, errors.New("must not be empty"))
			}
			sources[sourceIndex] = source
		}
		cfg.Groups = append(cfg.Groups, Group{Name: name, Sources: sources})
	}
	return cfg, nil
}

func prepareJSON(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		data = data[3:]
	}
	if !utf8.Valid(data) {
		return nil, configErr("CONFIG_ENCODING", "", errors.New("manifest is not valid UTF-8"))
	}
	if err := validateUnicodeEscapes(data); err != nil {
		return nil, configErr("CONFIG_ENCODING", "", err)
	}
	return data, nil
}

func applyDownload(cfg *Config, raw *downloadManifest) error {
	if raw == nil {
		return nil
	}
	if raw.Concurrency != nil {
		if *raw.Concurrency <= 0 {
			return configErr("CONFIG_VALUE", "download.concurrency", errors.New("must be positive"))
		}
		cfg.Download.Concurrency = *raw.Concurrency
	}
	if raw.PerHostConcurrency != nil {
		if *raw.PerHostConcurrency <= 0 {
			return configErr("CONFIG_VALUE", "download.per-host-concurrency", errors.New("must be positive"))
		}
		cfg.Download.PerHostConcurrency = *raw.PerHostConcurrency
	}
	if raw.Timeout != nil {
		duration, err := positiveDuration(*raw.Timeout)
		if err != nil {
			return configErr("CONFIG_VALUE", "download.timeout", err)
		}
		cfg.Download.Timeout = duration
	}
	if raw.ConnectTimeout != nil {
		duration, err := positiveDuration(*raw.ConnectTimeout)
		if err != nil {
			return configErr("CONFIG_VALUE", "download.connect-timeout", err)
		}
		cfg.Download.ConnectTimeout = duration
	}
	if raw.Retries != nil {
		if *raw.Retries < 0 {
			return configErr("CONFIG_VALUE", "download.retries", errors.New("must be non-negative"))
		}
		cfg.Download.Retries = *raw.Retries
	}
	if raw.Proxy != nil {
		cfg.Download.Proxy.Enabled = raw.Proxy.Enable
		if raw.Proxy.URL != nil {
			proxyURL, err := url.Parse(*raw.Proxy.URL)
			if err != nil || proxyURL.Host == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
				return configErr("CONFIG_VALUE", "download.proxy.url", errors.New("must be an absolute HTTP or HTTPS URL"))
			}
			cfg.Download.Proxy.URL = proxyURL
		}
		if raw.Proxy.Enable && cfg.Download.Proxy.URL == nil {
			return configErr("CONFIG_VALUE", "download.proxy.url", errors.New("is required when proxy is enabled"))
		}
	}
	return nil
}

func applyExtract(cfg *Config, raw *extractManifest) error {
	if raw == nil || raw.Concurrency == nil {
		return nil
	}
	if *raw.Concurrency <= 0 {
		return configErr("CONFIG_VALUE", "extract.concurrency", errors.New("must be positive"))
	}
	cfg.Extract.Concurrency = *raw.Concurrency
	return nil
}

func applyBuild(cfg *Config, raw *buildManifest) error {
	if raw == nil {
		return nil
	}
	if raw.MaxLineSize != nil {
		size, err := parseByteSize(*raw.MaxLineSize)
		if err != nil || size <= 0 {
			return configErr("CONFIG_VALUE", "build.max-line-size", errors.New("must be a positive byte size"))
		}
		cfg.Build.MaxLineSize = size
	}
	if raw.MaxDiagnostics != nil {
		if *raw.MaxDiagnostics < 0 {
			return configErr("CONFIG_VALUE", "build.max-diagnostics", errors.New("must be non-negative"))
		}
		cfg.Build.MaxDiagnostics = *raw.MaxDiagnostics
	}
	return nil
}

func positiveDuration(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, errors.New("must be a positive duration")
	}
	return duration, nil
}

func parseByteSize(value string) (int64, error) {
	units := []struct {
		suffix string
		factor int64
	}{
		{"GiB", 1024 * 1024 * 1024},
		{"MiB", 1024 * 1024},
		{"KiB", 1024},
		{"B", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			number := strings.TrimSuffix(value, unit.suffix)
			parsed, err := strconv.ParseInt(number, 10, 64)
			if err != nil || parsed <= 0 || parsed > (1<<63-1)/unit.factor {
				return 0, errors.New("invalid byte size")
			}
			return parsed * unit.factor, nil
		}
	}
	return 0, errors.New("invalid byte size unit")
}

func validateGroupName(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	for _, r := range value {
		if r == ',' || r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			return errors.New("contains a comma or control character")
		}
	}
	return nil
}

func trimFixedWhiteSpace(value string) string {
	return strings.TrimFunc(value, isFixedWhiteSpace)
}

func isFixedWhiteSpace(r rune) bool {
	return (r >= 0x0009 && r <= 0x000d) ||
		r == 0x0020 ||
		r == 0x0085 ||
		r == 0x00a0 ||
		r == 0x1680 ||
		(r >= 0x2000 && r <= 0x200a) ||
		r == 0x2028 ||
		r == 0x2029 ||
		r == 0x202f ||
		r == 0x205f ||
		r == 0x3000
}

func configErr(code, field string, err error) error {
	return &Error{Code: code, Field: field, Err: err}
}
