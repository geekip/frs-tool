package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"frs-tool/internal/config"
)

func TestHTTPAcquirerBasicAuthIdentityAndLongRedirectChain(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding = %q", request.Header.Get("Accept-Encoding"))
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "user name" || password != "secret:value" {
			t.Errorf("source Basic auth = %q/%q/%v", username, password, ok)
		}
		step, _ := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/"))
		if step < 12 {
			http.Redirect(writer, request, "/"+strconv.Itoa(step+1), http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("example.com"))
	}))
	defer server.Close()

	valueURL, err := url.Parse(server.URL + "/0")
	if err != nil {
		t.Fatal(err)
	}
	valueURL.User = url.UserPassword("user name", "secret:value")
	acquirer := NewHTTPAcquirer(testDownloadConfig(), WithRetryDelay(func(int) time.Duration { return 0 }))
	ref, err := acquirer.Acquire(context.Background(), remoteSource(1, valueURL))
	if err != nil {
		t.Fatal(err)
	}
	if actual := readRef(t, ref); actual != "example.com" {
		t.Fatalf("snapshot = %q", actual)
	}
	if requests.Load() != 13 {
		t.Fatalf("requests = %d, want 13", requests.Load())
	}
}

func TestHTTPAcquirerDoesNotCopySourceAuthAcrossHosts(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Errorf("Authorization crossed host boundary: %q", request.Header.Get("Authorization"))
		}
		_, _ = writer.Write([]byte("target.example"))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, _, ok := request.BasicAuth(); !ok {
			t.Error("initial source did not receive Basic auth")
		}
		crossHostURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
		http.Redirect(writer, request, crossHostURL, http.StatusFound)
	}))
	defer redirector.Close()

	valueURL, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatal(err)
	}
	valueURL.User = url.UserPassword("source-user", "source-secret")
	acquirer := NewHTTPAcquirer(testDownloadConfig())
	ref, err := acquirer.Acquire(context.Background(), remoteSource(1, valueURL))
	if err != nil {
		t.Fatal(err)
	}
	if actual := readRef(t, ref); actual != "target.example" {
		t.Fatalf("snapshot = %q", actual)
	}
}

func TestHTTPAcquirerResponseValidationAndRetry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		encoding    string
		contentType string
		body        []byte
		wantCode    string
	}{
		{"identity", "identity", "", []byte("example.com"), ""},
		{"mislabelled text", "", "application/octet-stream", []byte("example.com"), ""},
		{"gzip header", "gzip", "", []byte("example.com"), "SOURCE_CONTENT_ENCODING"},
		{"deflate header", "deflate", "", []byte("example.com"), "SOURCE_CONTENT_ENCODING"},
		{"brotli header", "br", "", []byte("example.com"), "SOURCE_CONTENT_ENCODING"},
		{"zstd header", "zstd", "", []byte("example.com"), "SOURCE_CONTENT_ENCODING"},
		{"unknown encoding", "custom", "", []byte("example.com"), "SOURCE_CONTENT_ENCODING"},
		{"gzip magic", "", "text/plain", []byte{0x1f, 0x8b, 0x08}, "SOURCE_INVALID_TEXT"},
		{"invalid UTF-8", "", "text/plain", []byte{0xff}, "SOURCE_INVALID_TEXT"},
		{"binary", "", "text/plain", []byte{'a', 0, 'b'}, "SOURCE_INVALID_TEXT"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if test.encoding != "" {
					writer.Header().Set("Content-Encoding", test.encoding)
				}
				if test.contentType != "" {
					writer.Header().Set("Content-Type", test.contentType)
				}
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(test.body)
			}))
			defer server.Close()
			acquirer := NewHTTPAcquirer(testDownloadConfig())
			_, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, server.URL))
			if test.wantCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || AsError(err).Code != test.wantCode {
				t.Fatalf("error = %v, want code %s", err, test.wantCode)
			}
		})
	}

	chunked := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = writer.Write([]byte("chunked.example"))
	}))
	defer chunked.Close()
	chunkedRef, err := NewHTTPAcquirer(testDownloadConfig()).Acquire(
		context.Background(),
		mustRemoteSource(t, 1, chunked.URL),
	)
	if err != nil || readRef(t, chunkedRef) != "chunked.example" {
		t.Fatalf("chunked text failed: %v", err)
	}

	var attempts atomic.Int64
	retryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if attempts.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = writer.Write([]byte("retry.example"))
	}))
	defer retryServer.Close()
	download := testDownloadConfig()
	download.Retries = 3
	acquirer := NewHTTPAcquirer(download, WithRetryDelay(func(int) time.Duration { return 0 }))
	if _, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, retryServer.URL)); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("retry attempts = %d", attempts.Load())
	}

	attempts.Store(0)
	authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer authServer.Close()
	_, err = acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, authServer.URL))
	if err == nil || AsError(err).Code != "SOURCE_AUTH" || attempts.Load() != 1 {
		t.Fatalf("authentication failure retried or misclassified: attempts=%d err=%v", attempts.Load(), err)
	}

	attempts.Store(0)
	proxyAuthFailure := roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusProxyAuthRequired,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("proxy authentication required")),
		}, nil
	})
	proxyAuthAcquirer := NewHTTPAcquirer(download, WithRoundTripper(proxyAuthFailure))
	_, err = proxyAuthAcquirer.Acquire(context.Background(), mustRemoteSource(t, 1, "http://example.test"))
	if err == nil || AsError(err).Code != "SOURCE_AUTH" || attempts.Load() != 1 {
		t.Fatalf("proxy authentication failure retried or misclassified: attempts=%d err=%v", attempts.Load(), err)
	}
}

func TestHTTPAcquirerProxyAuthIsolation(t *testing.T) {
	t.Parallel()
	const (
		sourceUser = "source-canary-user"
		sourcePass = "source-canary-pass"
		proxyUser  = "proxy-canary-user"
		proxyPass  = "proxy-canary-pass"
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != sourceUser || password != sourcePass {
			t.Errorf("upstream source auth = %q/%q/%v", username, password, ok)
		}
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential reached upstream")
		}
		_, _ = writer.Write([]byte("proxy.example"))
	}))
	defer upstream.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := request.Header.Get("Proxy-Authorization")
		if header == "" {
			t.Error("proxy did not receive proxy authentication")
		}
		outbound := request.Clone(request.Context())
		outbound.RequestURI = ""
		outbound.Header = request.Header.Clone()
		outbound.Header.Del("Proxy-Authorization")
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err != nil {
			http.Error(writer, "proxy failure", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, value := range values {
				writer.Header().Add(key, value)
			}
		}
		writer.WriteHeader(response.StatusCode)
		_, _ = io.Copy(writer, response.Body)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword(proxyUser, proxyPass)
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetURL.User = url.UserPassword(sourceUser, sourcePass)
	download := testDownloadConfig()
	download.Proxy = config.ProxyConfig{Enabled: true, URL: proxyURL}
	acquirer := NewHTTPAcquirer(download)
	ref, err := acquirer.Acquire(context.Background(), remoteSource(1, targetURL))
	if err != nil {
		t.Fatal(err)
	}
	if actual := readRef(t, ref); actual != "proxy.example" {
		t.Fatalf("snapshot = %q", actual)
	}
}

func TestHTTPAcquirerPerHostLimitDeadlineAndSafeErrors(t *testing.T) {
	t.Parallel()
	var active atomic.Int64
	var maximum atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		updateAtomicMaximum(&maximum, current)
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		_, _ = writer.Write([]byte("limit.example"))
	}))
	defer server.Close()
	download := testDownloadConfig()
	download.PerHostConcurrency = 3
	acquirer := NewHTTPAcquirer(download)
	var wait sync.WaitGroup
	for index := 0; index < 12; index++ {
		wait.Add(1)
		go func(id int) {
			defer wait.Done()
			_, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, uint32(id+1), server.URL+"/"+strconv.Itoa(id)))
			if err != nil {
				t.Errorf("Acquire: %v", err)
			}
		}(index)
	}
	wait.Wait()
	if maximum.Load() != 3 {
		t.Fatalf("per-host active = %d, want saturated limit 3", maximum.Load())
	}

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer timeoutServer.Close()
	timeoutConfig := testDownloadConfig()
	timeoutConfig.Timeout = 20 * time.Millisecond
	timeoutConfig.Retries = 3
	timeoutAcquirer := NewHTTPAcquirer(timeoutConfig, WithRetryDelay(func(int) time.Duration { return 0 }))
	_, err := timeoutAcquirer.Acquire(context.Background(), mustRemoteSource(t, 1, timeoutServer.URL))
	if err == nil || AsError(err).Code != "SOURCE_TIMEOUT" {
		t.Fatalf("deadline error = %v", err)
	}

	canaryError := errors.New("user-canary password-canary")
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, canaryError
	})
	safeAcquirer := NewHTTPAcquirer(testDownloadConfig(), WithRoundTripper(failing))
	_, err = safeAcquirer.Acquire(context.Background(), mustRemoteSource(t, 1, "http://user-canary:password-canary@example.test"))
	if err == nil {
		t.Fatal("failing transport succeeded")
	}
	if strings.Contains(err.Error(), "user-canary") || strings.Contains(err.Error(), "password-canary") {
		t.Fatalf("credential leaked through error: %v", err)
	}
}

func TestHTTPAcquirerRetriesCloseFailureWithoutCommitting(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int64
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       closeErrorBody{Reader: strings.NewReader("partial.example")},
		}, nil
	})
	download := testDownloadConfig()
	download.Retries = 1
	acquirer := NewHTTPAcquirer(download, WithRoundTripper(transport), WithRetryDelay(func(int) time.Duration { return 0 }))
	_, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, "http://example.test"))
	if err == nil || AsError(err).Code != "SOURCE_CLOSE" {
		t.Fatalf("close failure = %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

func TestHTTPAcquirerAllowsProtocolRedirectsAndBoundsLoopsByDeadline(t *testing.T) {
	t.Parallel()
	httpTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("downgrade.example"))
	}))
	defer httpTarget.Close()

	var tlsServer *httptest.Server
	tlsServer = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/down":
			http.Redirect(writer, request, httpTarget.URL, http.StatusFound)
		case "/loop":
			http.Redirect(writer, request, tlsServer.URL+"/loop", http.StatusFound)
		default:
			_, _ = writer.Write([]byte("upgrade.example"))
		}
	}))
	defer tlsServer.Close()
	httpRedirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, tlsServer.URL+"/up", http.StatusFound)
	}))
	defer httpRedirect.Close()

	pool := x509.NewCertPool()
	addServerCertificate(t, pool, tlsServer)
	acquirer := NewHTTPAcquirer(testDownloadConfig(), WithTLSConfig(tlsConfigFor(pool)))
	ref, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, httpRedirect.URL))
	if err != nil || readRef(t, ref) != "upgrade.example" {
		t.Fatalf("HTTP to HTTPS redirect failed: %v", err)
	}
	ref, err = acquirer.Acquire(context.Background(), mustRemoteSource(t, 2, tlsServer.URL+"/down"))
	if err != nil || readRef(t, ref) != "downgrade.example" {
		t.Fatalf("HTTPS to HTTP redirect failed: %v", err)
	}

	loopConfig := testDownloadConfig()
	loopConfig.Timeout = 30 * time.Millisecond
	loopAcquirer := NewHTTPAcquirer(loopConfig, WithTLSConfig(tlsConfigFor(pool)))
	_, err = loopAcquirer.Acquire(context.Background(), mustRemoteSource(t, 3, tlsServer.URL+"/loop"))
	if err == nil || AsError(err).Code != "SOURCE_TIMEOUT" {
		t.Fatalf("redirect loop did not end at source deadline: %v", err)
	}
}

func TestHTTPAcquirerSupportsHTTPAndHTTPSConnectProxies(t *testing.T) {
	t.Parallel()
	targetHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "source-user" || password != "source-pass" {
			t.Errorf("target source auth = %q/%q/%v", username, password, ok)
		}
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy authorization reached HTTPS target")
		}
		_, _ = writer.Write([]byte("secure-proxy.example"))
	})
	httpTarget := httptest.NewServer(targetHandler)
	defer httpTarget.Close()
	httpsTarget := httptest.NewTLSServer(targetHandler)
	defer httpsTarget.Close()

	var proxyAuthCount atomic.Int64
	handler := connectProxyHandler(t, &proxyAuthCount)
	httpProxy := httptest.NewServer(handler)
	defer httpProxy.Close()
	httpsProxy := httptest.NewTLSServer(handler)
	defer httpsProxy.Close()

	pool := x509.NewCertPool()
	addServerCertificate(t, pool, httpsTarget)
	addServerCertificate(t, pool, httpsProxy)

	for _, rawProxyURL := range []string{httpProxy.URL, httpsProxy.URL} {
		proxyURL, err := url.Parse(rawProxyURL)
		if err != nil {
			t.Fatal(err)
		}
		proxyURL.User = url.UserPassword("proxy-user", "proxy-pass")
		download := testDownloadConfig()
		download.Proxy = config.ProxyConfig{Enabled: true, URL: proxyURL}
		for targetIndex, rawTargetURL := range []string{httpTarget.URL, httpsTarget.URL} {
			targetURL, err := url.Parse(rawTargetURL)
			if err != nil {
				t.Fatal(err)
			}
			targetURL.User = url.UserPassword("source-user", "source-pass")
			acquirer := NewHTTPAcquirer(download, WithTLSConfig(tlsConfigFor(pool)))
			ref, err := acquirer.Acquire(context.Background(), remoteSource(uint32(targetIndex+1), targetURL))
			if err != nil {
				t.Fatalf("%s source through %s proxy: %v", targetURL.Scheme, proxyURL.Scheme, err)
			}
			if actual := readRef(t, ref); actual != "secure-proxy.example" {
				t.Fatalf("%s source through %s proxy snapshot = %q", targetURL.Scheme, proxyURL.Scheme, actual)
			}
		}
	}
	if proxyAuthCount.Load() != 4 {
		t.Fatalf("authenticated proxy requests = %d, want 4", proxyAuthCount.Load())
	}
}

func TestHTTPAcquirerRejectsTruncatedBodyAndInvalidRedirect(t *testing.T) {
	t.Parallel()
	truncated := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hijacker := writer.(http.Hijacker)
		connection, buffered, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
		_ = buffered.Flush()
		_ = connection.Close()
	}))
	defer truncated.Close()
	acquirer := NewHTTPAcquirer(testDownloadConfig())
	_, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, truncated.URL))
	if err == nil || AsError(err).Code != "SOURCE_READ" {
		t.Fatalf("truncated response = %v", err)
	}

	var invalidRedirectRequests atomic.Int64
	invalidRedirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		invalidRedirectRequests.Add(1)
		writer.Header().Set("Location", "://invalid")
		writer.WriteHeader(http.StatusFound)
	}))
	defer invalidRedirect.Close()
	retryConfig := testDownloadConfig()
	retryConfig.Retries = 3
	retryAcquirer := NewHTTPAcquirer(retryConfig, WithRetryDelay(func(int) time.Duration { return 0 }))
	_, err = retryAcquirer.Acquire(context.Background(), mustRemoteSource(t, 2, invalidRedirect.URL))
	if err == nil || AsError(err).Code != "SOURCE_NETWORK" || invalidRedirectRequests.Load() != 1 {
		t.Fatalf("invalid redirect = %v", err)
	}

	var unsupportedRequests atomic.Int64
	unsupportedRedirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		unsupportedRequests.Add(1)
		writer.Header().Set("Location", "ftp://example.test/list")
		writer.WriteHeader(http.StatusFound)
	}))
	defer unsupportedRedirect.Close()
	_, err = retryAcquirer.Acquire(context.Background(), mustRemoteSource(t, 3, unsupportedRedirect.URL))
	if err == nil || AsError(err).Code != "SOURCE_NETWORK" || unsupportedRequests.Load() != 1 {
		t.Fatalf("unsupported redirect = %v, requests=%d", err, unsupportedRequests.Load())
	}
}

func TestHTTPAcquirerDoesNotRetryCertificateOrConnectProxyAuthFailures(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int64
	certificateFailure := roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, x509.UnknownAuthorityError{}
	})
	download := testDownloadConfig()
	download.Retries = 3
	acquirer := NewHTTPAcquirer(download, WithRoundTripper(certificateFailure), WithRetryDelay(func(int) time.Duration { return 0 }))
	_, err := acquirer.Acquire(context.Background(), mustRemoteSource(t, 1, "https://example.test"))
	if err == nil || attempts.Load() != 1 {
		t.Fatalf("certificate failure retried: attempts=%d err=%v", attempts.Load(), err)
	}

	attempts.Store(0)
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		writer.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	proxyURL, parseError := url.Parse(proxy.URL)
	if parseError != nil {
		t.Fatal(parseError)
	}
	download.Proxy = config.ProxyConfig{Enabled: true, URL: proxyURL}
	proxyAcquirer := NewHTTPAcquirer(download, WithRetryDelay(func(int) time.Duration { return 0 }))
	_, err = proxyAcquirer.Acquire(context.Background(), mustRemoteSource(t, 2, "https://example.test"))
	if err == nil || AsError(err).Code != "SOURCE_AUTH" || attempts.Load() != 1 {
		t.Fatalf("CONNECT proxy authentication failure retried: attempts=%d err=%v", attempts.Load(), err)
	}
}

func testDownloadConfig() config.DownloadConfig {
	return config.DownloadConfig{
		Concurrency:        10,
		PerHostConcurrency: 3,
		Timeout:            2 * time.Second,
		ConnectTimeout:     time.Second,
		Retries:            0,
	}
}

func mustRemoteSource(t *testing.T, id uint32, rawURL string) PhysicalSource {
	t.Helper()
	value, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return remoteSource(id, value)
}

func remoteSource(id uint32, value *url.URL) PhysicalSource {
	return NewRemoteSource(id, value)
}

func readRef(t *testing.T, ref FileRef) string {
	t.Helper()
	reader, err := ref.Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func updateAtomicMaximum(target *atomic.Int64, value int64) {
	for {
		current := target.Load()
		if value <= current || target.CompareAndSwap(current, value) {
			return
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type closeErrorBody struct {
	io.Reader
}

func (closeErrorBody) Close() error {
	return errors.New("close failed")
}

func addServerCertificate(t *testing.T, pool *x509.CertPool, server *httptest.Server) {
	t.Helper()
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(certificate)
}

func tlsConfigFor(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func connectProxyHandler(t *testing.T, count *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") == "" {
			http.Error(writer, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		count.Add(1)
		if request.Method != http.MethodConnect {
			outbound := request.Clone(request.Context())
			outbound.RequestURI = ""
			outbound.Header = request.Header.Clone()
			outbound.Header.Del("Proxy-Authorization")
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			response, err := transport.RoundTrip(outbound)
			if err != nil {
				http.Error(writer, "forward failure", http.StatusBadGateway)
				return
			}
			defer response.Body.Close()
			for key, values := range response.Header {
				for _, value := range values {
					writer.Header().Add(key, value)
				}
			}
			writer.WriteHeader(response.StatusCode)
			_, _ = io.Copy(writer, response.Body)
			return
		}
		upstream, err := net.Dial("tcp", request.Host)
		if err != nil {
			http.Error(writer, "dial failure", http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			upstream.Close()
			http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			client.Close()
			upstream.Close()
			return
		}
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	})
}
