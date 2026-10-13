package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"frs-tool/internal/config"
)

// Kind 表示物理来源的取得方式。
type Kind uint8

const (
	KindInvalid Kind = iota
	KindLocal
	KindRemote
)

// SourceBinding 将配置中的来源 occurrence 关联到物理来源。
type SourceBinding struct {
	PhysicalID  uint32
	GroupID     uint32
	SourceIndex uint32
}

// PhysicalSource 是去重后的实际采集单元。
type PhysicalSource struct {
	ID        uint32
	Kind      Kind
	Location  string
	LocalPath string
	KeyID     string
	remoteURL *url.URL
	issue     *Error
}

// NewRemoteSource 创建持有私有完整 URL、仅公开脱敏位置的远程来源。
func NewRemoteSource(id uint32, value *url.URL) PhysicalSource {
	if value == nil || value.Host == "" ||
		(!strings.EqualFold(value.Scheme, "http") && !strings.EqualFold(value.Scheme, "https")) {
		invalid := invalidSource(RedactURL(value), "SOURCE_INVALID_URL", "invalid remote source URL")
		invalid.ID = id
		return invalid
	}
	remoteURL := cloneURL(value)
	remoteURL.Scheme = strings.ToLower(remoteURL.Scheme)
	return PhysicalSource{
		ID:        id,
		Kind:      KindRemote,
		Location:  RedactURL(value),
		remoteURL: remoteURL,
	}
}

// String 只返回可安全展示的脱敏位置。
func (s PhysicalSource) String() string {
	return s.Location
}

// Issue 返回来源定位阶段发现的安全错误。
func (s PhysicalSource) Issue() error {
	if s.issue == nil {
		return nil
	}
	copy := *s.issue
	return &copy
}

// Index 保存稳定物理来源表和全部 occurrence binding。
type Index struct {
	Sources  []PhysicalSource
	Bindings []SourceBinding
}

// Flatten 将组内来源展开为稳定的物理来源和多对多绑定。
func Flatten(cfg config.Config) Index {
	var result Index
	byKey := make(map[string]uint32)
	for groupIndex, group := range cfg.Groups {
		for sourceIndex, value := range group.Sources {
			physical, rawKey := resolve(cfg, value)
			id, exists := byKey[rawKey]
			if !exists {
				id = uint32(len(result.Sources) + 1)
				physical.ID = id
				physical.KeyID = hashKey(rawKey)
				result.Sources = append(result.Sources, physical)
				byKey[rawKey] = id
			}
			result.Bindings = append(result.Bindings, SourceBinding{
				PhysicalID:  id,
				GroupID:     uint32(groupIndex + 1),
				SourceIndex: uint32(sourceIndex + 1),
			})
		}
	}
	return result
}

func resolve(cfg config.Config, value string) (PhysicalSource, string) {
	if isWindowsDrivePath(value) {
		return resolveLocal(cfg.BaseDir, value)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		location := redactInvalidURL(value)
		return invalidSource(location, "SOURCE_INVALID_URL", "invalid source URL"), "invalid\x00" + value
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "":
		return resolveLocal(cfg.BaseDir, value)
	case "file":
		path, err := fileURLPath(parsed)
		if err != nil {
			location := RedactURL(parsed)
			return invalidSource(location, "SOURCE_INVALID_FILE_URL", "invalid file URL"), "invalid-file\x00" + value
		}
		return resolveLocal(cfg.BaseDir, path)
	case "http", "https":
		if parsed.Host == "" {
			location := RedactURL(parsed)
			return invalidSource(location, "SOURCE_INVALID_URL", "remote URL has no host"), "invalid-remote\x00" + value
		}
		proxyKey := "direct"
		if cfg.Download.Proxy.Enabled && cfg.Download.Proxy.URL != nil {
			proxyKey = cfg.Download.Proxy.URL.String()
		}
		key := "remote\x00" + parsed.String() + "\x00" + proxyKey
		return NewRemoteSource(0, parsed), key
	default:
		location := RedactURL(parsed)
		return invalidSource(location, "SOURCE_UNSUPPORTED_SCHEME", "unsupported source scheme"), "unsupported\x00" + value
	}
}

func resolveLocal(baseDir, value string) (PhysicalSource, string) {
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return invalidSource("<invalid-path>", "SOURCE_INVALID_PATH", "invalid local path"), "invalid-path\x00" + value
	}
	absolute = filepath.Clean(absolute)
	if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = evaluated
	}
	return PhysicalSource{
		Kind:      KindLocal,
		Location:  absolute,
		LocalPath: absolute,
	}, "local\x00" + absolute
}

func invalidSource(location, code, message string) PhysicalSource {
	return PhysicalSource{
		Kind:     KindInvalid,
		Location: location,
		issue:    NewError(code, message, false, nil),
	}
}

func fileURLPath(value *url.URL) (string, error) {
	if value.User != nil || value.RawQuery != "" || value.Fragment != "" || value.Opaque != "" {
		return "", errors.New("unsupported file URL component")
	}
	if value.Host != "" && !strings.EqualFold(value.Host, "localhost") {
		return "", errors.New("non-local file authority")
	}
	path := value.Path
	if path == "" {
		return "", errors.New("empty file URL path")
	}
	if runtime.GOOS == "windows" && len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	return filepath.FromSlash(path), nil
}

func isWindowsDrivePath(value string) bool {
	return len(value) >= 2 &&
		((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) &&
		value[1] == ':'
}

func hashKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// RedactURL 返回不含 userinfo 的诊断位置。
func RedactURL(value *url.URL) string {
	if value == nil {
		return "<invalid-url>"
	}
	copy := *value
	copy.User = nil
	return copy.String()
}

func redactInvalidURL(value string) string {
	if strings.Contains(value, "://") {
		return "<invalid-url>"
	}
	return "<invalid-source>"
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

type refKind uint8

const (
	refLocal refKind = iota + 1
	refMemory
	refReader
)

// FileRef 是已就绪来源的不可变读取引用。
type FileRef struct {
	SourceID uint32
	Location string
	kind     refKind
	path     string
	data     []byte
	open     func() (io.ReadCloser, error)
}

// LocalRef 创建延迟打开的本地文件引用。
func LocalRef(value PhysicalSource) FileRef {
	return FileRef{
		SourceID: value.ID,
		Location: value.Location,
		kind:     refLocal,
		path:     value.LocalPath,
	}
}

// MemoryRef 复制完整正文并创建不可变内存引用。
func MemoryRef(sourceID uint32, location string, data []byte) FileRef {
	copy := append([]byte(nil), data...)
	return FileRef{
		SourceID: sourceID,
		Location: location,
		kind:     refMemory,
		data:     copy,
	}
}

// ReaderRef 为受控适配器和故障测试创建读取引用。
func ReaderRef(sourceID uint32, location string, open func() (io.ReadCloser, error)) FileRef {
	return FileRef{
		SourceID: sourceID,
		Location: location,
		kind:     refReader,
		open:     open,
	}
}

// Open 为一次完整提取打开独立 reader。
func (r FileRef) Open() (io.ReadCloser, error) {
	switch r.kind {
	case refLocal:
		return os.Open(r.path)
	case refMemory:
		return io.NopCloser(bytes.NewReader(r.data)), nil
	case refReader:
		if r.open == nil {
			return nil, errors.New("reader factory is nil")
		}
		return r.open()
	default:
		return nil, errors.New("invalid source reference")
	}
}

// Error 是不会泄露 URL 凭据的来源错误。
type Error struct {
	Code      string
	Message   string
	Retryable bool
	cause     error
}

// NewError 创建稳定的来源错误。
func NewError(code, message string, retryable bool, cause error) *Error {
	return &Error{Code: code, Message: message, Retryable: retryable, cause: cause}
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.cause
}

// AsError 将任意错误收敛为可安全展示的来源错误。
func AsError(err error) *Error {
	var sourceError *Error
	if errors.As(err, &sourceError) {
		copy := *sourceError
		return &copy
	}
	return NewError("SOURCE_UNAVAILABLE", "source unavailable", false, err)
}
