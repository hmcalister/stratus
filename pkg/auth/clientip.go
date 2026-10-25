package auth

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// Returns a ClientIP function for an app behind a reverse proxy. Pass it as AuthServiceConfig.ClientIP.
//
// The X-Forwarded-For header is read only when the immediate peer is inside one of trustedProxies. The header is then read from right to left, skipping addresses inside trustedProxies, and the first untrusted address is returned. When the header is absent or contains an address that cannot be parsed, the peer address is returned instead.
//
// List only proxies that you control. If clients can reach the app without passing through them, they can forge the header.
func TrustedProxyClientIP(trustedProxies []netip.Prefix) func(*http.Request) string {
	trusted := slices.Clone(trustedProxies)

	return func(r *http.Request) string {
		peer := remoteAddrHost(r.RemoteAddr)

		peerAddr, err := netip.ParseAddr(peer)
		if err != nil {
			return peer
		}
		peerAddr = peerAddr.Unmap()
		if !isTrustedProxy(peerAddr, trusted) {
			return peerAddr.String()
		}

		values := r.Header.Values("X-Forwarded-For")
		if len(values) == 0 {
			return peerAddr.String()
		}

		entries := strings.Split(strings.Join(values, ","), ",")
		for i := len(entries) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
			if err != nil {
				return peerAddr.String()
			}
			addr = addr.Unmap()
			if isTrustedProxy(addr, trusted) {
				continue
			}
			return addr.String()
		}
		return peerAddr.String()
	}
}

// Returns the host part of the request's RemoteAddr, falling back to the whole value when it has no port.
func remoteAddrClientIP(r *http.Request) string {
	return remoteAddrHost(r.RemoteAddr)
}

// Returns the host part of a network address, falling back to the whole value when it has no port.
func remoteAddrHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Reports whether addr falls inside one of trustedProxies.
func isTrustedProxy(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
