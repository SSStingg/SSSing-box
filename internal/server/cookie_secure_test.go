package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsHTTPSRequest(t *testing.T) {
	mk := func(tlsConn bool, remote, proto string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tlsConn {
			r.TLS = &tls.ConnectionState{}
		}
		r.RemoteAddr = remote
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		return r
	}
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"直连 TLS", mk(true, "1.2.3.4:1234", ""), true},
		{"明文直连", mk(false, "1.2.3.4:1234", ""), false},
		{"回环反代 https", mk(false, "127.0.0.1:58081", "https"), true},
		{"回环反代 http", mk(false, "127.0.0.1:58081", "http"), false},
		{"回环反代无头", mk(false, "127.0.0.1:58081", ""), false},
		{"外网伪造反代头", mk(false, "1.2.3.4:1234", "https"), false},
		{"IPv6 回环反代 https", mk(false, "[::1]:58081", "https"), true},
		{"nil 请求", nil, false},
	}
	for _, c := range cases {
		if got := isHTTPSRequest(c.req); got != c.want {
			t.Errorf("%s：得到 %v，想要 %v", c.name, got, c.want)
		}
	}
}
