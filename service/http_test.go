package service

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/dial"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestHTTPProxyClosesUpstreamResponseBody(t *testing.T) {
	body := &trackingBody{Reader: bytes.NewBufferString("response")}
	proxy := newHTTPProxy(dial.NewDialer(nil, nil, nil, false, ""))
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       body,
		}, nil
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	proxy.ServeHTTP(recorder, req)

	if !body.closed.Load() {
		t.Fatal("upstream response body was not closed")
	}
}

func TestHTTPProxyTransportHasBoundedPool(t *testing.T) {
	proxy := newHTTPProxy(dial.NewDialer(nil, nil, nil, false, ""))
	transport, ok := proxy.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", proxy.client.Transport)
	}
	if transport.MaxIdleConns <= 0 || transport.MaxIdleConnsPerHost <= 0 {
		t.Fatalf("idle limits = global %d, per-host %d; want positive", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
	if transport.MaxConnsPerHost <= 0 {
		t.Fatalf("MaxConnsPerHost = %d, want positive", transport.MaxConnsPerHost)
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("IdleConnTimeout is not configured")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("ResponseHeaderTimeout is not configured")
	}
}

func TestHTTPServerBoundsInboundIdleConnections(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is not configured")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is not configured")
	}
}

func TestHTTPConnectClosesTargetWhenClientDisconnects(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetListener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	proxy := httptest.NewServer(newHTTPHandler(dial.NewDialer(nil, nil, nil, false, "")))
	defer proxy.Close()

	clientConn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetListener.Addr(), targetListener.Addr()); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var targetConn net.Conn
	select {
	case targetConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy did not connect to target")
	}
	defer targetConn.Close()

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close proxy client: %v", err)
	}
	if err := targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set target read deadline: %v", err)
	}
	var buf [1]byte
	if _, err := targetConn.Read(buf[:]); err == nil {
		t.Fatal("target connection remained readable after proxy client disconnected")
	} else if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
		t.Fatal("target connection was not closed after proxy client disconnected")
	}
}

// 代理收到 origin-form（只有 path，没有 scheme/host）时，必须用 Host 头
// 补全目标地址，而不是把相对 URL 交给 Transport。
// 复现自 dae 走 HTTP 代理的场景：不修会得到
// `Get "/demo/": unsupported protocol scheme ""`。
func TestHTTPProxyOriginFormUsesHostHeader(t *testing.T) {
	proxy := newHTTPProxy(dial.NewDialer(nil, nil, nil, false, ""))

	var gotURL string
	proxy.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("ok")),
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/demo/", nil)
	req.Host = "192.0.2.10:8080"

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if gotURL != "http://192.0.2.10:8080/demo/" {
		t.Fatalf("upstream URL = %q, want http://192.0.2.10:8080/demo/", gotURL)
	}
}

// 缺少 Host 头时必须明确拒绝，而不是拼出一个无意义的 URL。
func TestHTTPProxyOriginFormWithoutHost(t *testing.T) {
	proxy := newHTTPProxy(dial.NewDialer(nil, nil, nil, false, ""))
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("upstream must not be called without a host")
		return nil, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/demo/", nil)
	req.Host = ""

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
