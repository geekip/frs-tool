package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"frs-tool/internal/config"
)

// HTTPOption 调整 HTTP 采集器的可测试边界。
type HTTPOption func(*httpOptions)

type httpOptions struct {
	roundTripper http.RoundTripper
	retryDelay   func(int) time.Duration
	tlsConfig    *tls.Config
}

// WithRoundTripper 注入底层传输；并发限制仍包裹该传输。
func WithRoundTripper(roundTripper http.RoundTripper) HTTPOption {
	return func(options *httpOptions) {
		options.roundTripper = roundTripper
	}
}

// WithRetryDelay 注入额外重试前的等待策略。
func WithRetryDelay(delay func(int) time.Duration) HTTPOption {
	return func(options *httpOptions) {
		options.retryDelay = delay
	}
}

// WithTLSConfig 注入测试或宿主明确提供的 TLS 配置副本。
func WithTLSConfig(tlsConfig *tls.Config) HTTPOption {
	return func(options *httpOptions) {
		if tlsConfig != nil {
			options.tlsConfig = tlsConfig.Clone()
		}
	}
}

// HTTPAcquirer 取得完整、已验证的远程内存快照。
type HTTPAcquirer struct {
	client  *http.Client
	timeout time.Duration
	retries int
	delay   func(int) time.Duration
}

// NewHTTPAcquirer 创建禁用透明解压和环境代理的共享客户端。
func NewHTTPAcquirer(download config.DownloadConfig, options ...HTTPOption) *HTTPAcquirer {
	settings := httpOptions{
		retryDelay: func(attempt int) time.Duration {
			delay := 100 * time.Millisecond
			for i := 0; i < attempt && delay < time.Second; i++ {
				delay *= 2
			}
			if delay > time.Second {
				return time.Second
			}
			return delay
		},
	}
	for _, option := range options {
		option(&settings)
	}

	var transport http.RoundTripper
	if settings.roundTripper != nil {
		transport = settings.roundTripper
	} else {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = nil
		base.DisableCompression = true
		base.TLSClientConfig = settings.tlsConfig
		base.DialContext = (&net.Dialer{
			Timeout:   download.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
		if download.Proxy.Enabled && download.Proxy.URL != nil {
			base.Proxy = http.ProxyURL(download.Proxy.URL)
		}
		transport = base
	}
	transport = newHostLimitedTransport(transport, download.PerHostConcurrency)

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			applyURLBasicAuth(request)
			return nil
		},
	}
	return &HTTPAcquirer{
		client:  client,
		timeout: download.Timeout,
		retries: download.Retries,
		delay:   settings.retryDelay,
	}
}

// Acquire 下载一个远程来源，失败 attempt 不会暴露部分正文。
func (a *HTTPAcquirer) Acquire(ctx context.Context, value PhysicalSource) (FileRef, error) {
	if value.Kind != KindRemote || value.remoteURL == nil {
		return FileRef{}, NewError("SOURCE_INVALID_URL", "source is not a remote URL", false, nil)
	}
	sourceContext, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	var lastError error
	for attempt := 0; attempt <= a.retries; attempt++ {
		ref, retry, err := a.attempt(sourceContext, value)
		if err == nil {
			return ref, nil
		}
		lastError = err
		if !retry || attempt == a.retries {
			break
		}
		if err := waitRetry(sourceContext, a.delay(attempt)); err != nil {
			lastError = contextSourceError(sourceContext.Err())
			break
		}
	}
	if sourceContext.Err() != nil {
		return FileRef{}, contextSourceError(sourceContext.Err())
	}
	return FileRef{}, lastError
}

func (a *HTTPAcquirer) attempt(ctx context.Context, value PhysicalSource) (FileRef, bool, error) {
	requestURL := cloneURL(value.remoteURL)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return FileRef{}, false, NewError("SOURCE_INVALID_URL", "cannot create source request", false, err)
	}
	request.Header.Set("Accept-Encoding", "identity")
	applyURLBasicAuth(request)

	response, err := a.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return FileRef{}, false, contextSourceError(ctx.Err())
		}
		if isProxyAuthenticationError(err) {
			return FileRef{}, false, NewError("SOURCE_AUTH", "remote source authentication failed", false, err)
		}
		retry := retryableTransportError(err)
		return FileRef{}, retry, NewError("SOURCE_NETWORK", "remote request failed", retry, err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		retry := retryableStatus(response.StatusCode)
		code := "SOURCE_HTTP_STATUS"
		message := "remote source returned an unsuccessful status"
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusProxyAuthRequired {
			code = "SOURCE_AUTH"
			message = "remote source authentication failed"
			retry = false
		}
		return FileRef{}, retry, NewError(code, message, retry, nil)
	}

	encoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		_ = response.Body.Close()
		return FileRef{}, false, NewError("SOURCE_CONTENT_ENCODING", "compressed response is not supported", false, nil)
	}

	data, readError := io.ReadAll(response.Body)
	closeError := response.Body.Close()
	if readError != nil {
		return FileRef{}, true, NewError("SOURCE_READ", "cannot read complete remote source", true, readError)
	}
	if closeError != nil {
		return FileRef{}, true, NewError("SOURCE_CLOSE", "cannot close remote response", true, closeError)
	}
	if err := ValidateText(data); err != nil {
		return FileRef{}, false, err
	}
	return MemoryRef(value.ID, value.Location, data), false, nil
}

func applyURLBasicAuth(request *http.Request) {
	if request == nil || request.URL == nil || request.URL.User == nil {
		return
	}
	username := request.URL.User.Username()
	password, _ := request.URL.User.Password()
	request.SetBasicAuth(username, password)
	copy := *request.URL
	copy.User = nil
	request.URL = &copy
}

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests ||
		(status >= 500 && status <= 599 && status != http.StatusNotImplemented)
}

func retryableTransportError(err error) bool {
	var verificationError *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	if errors.As(err, &verificationError) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &certificateInvalid) ||
		errors.As(err, &hostnameError) {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unsupported protocol scheme",
		"failed to parse location header",
	} {
		if strings.Contains(message, marker) {
			return false
		}
	}
	return true
}

func isProxyAuthenticationError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "proxy authentication required") ||
		strings.Contains(message, "status code 407")
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func contextSourceError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return NewError("SOURCE_TIMEOUT", "source deadline exceeded", false, err)
	}
	return NewError("SOURCE_CANCELED", "source acquisition canceled", false, err)
}

type hostLimitedTransport struct {
	next  http.RoundTripper
	limit int
	mu    sync.Mutex
	sems  map[string]chan struct{}
}

func newHostLimitedTransport(next http.RoundTripper, limit int) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	if limit < 1 {
		limit = 1
	}
	return &hostLimitedTransport{
		next:  next,
		limit: limit,
		sems:  make(map[string]chan struct{}),
	}
}

func (t *hostLimitedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	key := hostKey(request.URL)
	semaphore := t.semaphore(key)
	select {
	case semaphore <- struct{}{}:
	case <-request.Context().Done():
		return nil, request.Context().Err()
	}
	response, err := t.next.RoundTrip(request)
	if err != nil {
		<-semaphore
		return nil, err
	}
	response.Body = &releaseBody{
		ReadCloser: response.Body,
		release: func() {
			<-semaphore
		},
	}
	return response, nil
}

func (t *hostLimitedTransport) semaphore(key string) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	semaphore := t.sems[key]
	if semaphore == nil {
		semaphore = make(chan struct{}, t.limit)
		t.sems[key] = semaphore
	}
	return semaphore
}

func hostKey(value *url.URL) string {
	if value == nil {
		return ""
	}
	host := strings.ToLower(value.Hostname())
	if host == "" {
		host = strings.ToLower(value.Host)
	}
	return host
}

type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
