package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestTrustedProxyClientIP(t *testing.T) {
	clientIP := TrustedProxyClientIP([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})

	tests := []struct {
		name       string
		remoteAddr string
		headers    []string
		want       string
	}{
		{
			name:       "untrusted peer ignores header",
			remoteAddr: "203.0.113.9:1234",
			headers:    []string{"198.51.100.7"},
			want:       "203.0.113.9",
		},
		{
			name:       "trusted peer without header",
			remoteAddr: "10.0.0.5:1234",
			want:       "10.0.0.5",
		},
		{
			name:       "trusted peer without port",
			remoteAddr: "10.0.0.5",
			want:       "10.0.0.5",
		},
		{
			name:       "trusted peer with single entry",
			remoteAddr: "10.0.0.5:1234",
			headers:    []string{"198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "trusted peer with chain",
			remoteAddr: "10.0.0.5:1234",
			headers:    []string{"198.51.100.7, 10.0.0.2"},
			want:       "198.51.100.7",
		},
		{
			name:       "all entries trusted",
			remoteAddr: "10.0.0.5:1234",
			headers:    []string{"10.0.0.2, 10.0.0.3"},
			want:       "10.0.0.5",
		},
		{
			name:       "malformed entry",
			remoteAddr: "10.0.0.5:1234",
			headers:    []string{"not-an-ip"},
			want:       "10.0.0.5",
		},
		{
			name:       "multiple header values",
			remoteAddr: "10.0.0.5:1234",
			headers:    []string{"198.51.100.7", "10.0.0.2"},
			want:       "198.51.100.7",
		},
		{
			name:       "ipv6 trusted peer",
			remoteAddr: "[2001:db8::5]:1234",
			headers:    []string{"2001:db9::7"},
			want:       "2001:db9::7",
		},
		{
			name:       "ipv4 mapped peer",
			remoteAddr: "[::ffff:10.0.0.5]:1234",
			headers:    []string{"198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "malformed peer",
			remoteAddr: "unknown",
			headers:    []string{"198.51.100.7"},
			want:       "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.remoteAddr
			for _, value := range test.headers {
				request.Header.Add("X-Forwarded-For", value)
			}

			if got := clientIP(request); got != test.want {
				t.Errorf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRemoteAddrClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{name: "ipv4 with port", remoteAddr: "192.0.2.1:1234", want: "192.0.2.1"},
		{name: "ipv6 with port", remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "without port", remoteAddr: "192.0.2.1", want: "192.0.2.1"},
		{name: "empty", remoteAddr: "", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.remoteAddr

			if got := remoteAddrClientIP(request); got != test.want {
				t.Errorf("remoteAddrClientIP = %q, want %q", got, test.want)
			}
		})
	}
}
