package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	insecureSessionCookieName = "stratus_session"
	secureSessionCookieName   = "__Host-stratus_session"
)

// Configures the session cookie. HttpOnly is always set.
type CookieConfig struct {
	// The cookie name.
	//
	// Defaults to "__Host-stratus_session" when Secure is set and "stratus_session" otherwise.
	Name string

	// Scopes the cookie.
	//
	// Leave empty for a host-only cookie.
	Domain string

	// Scopes the cookie.
	//
	// Defaults to "/".
	Path string

	// Forces the cookie to be HTTPS-only.
	//
	// When false, the cookie is still Secure whenever BaseURL uses https, so production is secure by default.
	// Set it to true only when BaseURL uses http but the app is served over HTTPS, for example behind a TLS-terminating proxy.
	Secure bool

	// Controls cross-site sending.
	//
	// Defaults to SameSiteLaxMode.
	SameSite http.SameSite
}

func (cfg CookieConfig) withDefaultConfig() CookieConfig {
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteLaxMode
	}
	if cfg.Name == "" {
		cfg.Name = insecureSessionCookieName
		// The __Host- prefix requires a host-only cookie at the root path.
		if cfg.Secure && cfg.Domain == "" && cfg.Path == "/" {
			cfg.Name = secureSessionCookieName
		}
	}
	return cfg
}

// Reports cookie settings that the browser would reject, or that would break the guarantees of the __Host- prefix.
func (cfg CookieConfig) validate() error {
	probe := http.Cookie{Name: cfg.Name, Value: "session"}
	if err := probe.Valid(); err != nil {
		return fmt.Errorf("invalid cookie config: %w", err)
	}

	if strings.HasPrefix(cfg.Name, "__Host-") {
		if !cfg.Secure {
			return errors.New("__Host- cookie name requires a secure cookie")
		}
		if cfg.Path != "/" {
			return errors.New(`__Host- cookie name requires path "/"`)
		}
		if cfg.Domain != "" {
			return errors.New("__Host- cookie name must not set a domain")
		}
	}
	return nil
}

// Returns the cookie that carries rawToken. The cookie expires with the session.
func (s *AuthService) sessionCookie(rawToken string) *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.Cookie.Name,
		Value:    rawToken,
		Path:     s.cfg.Cookie.Path,
		Domain:   s.cfg.Cookie.Domain,
		Expires:  s.cfg.Now().Add(s.cfg.SessionTTL),
		MaxAge:   int(s.cfg.SessionTTL / time.Second),
		HttpOnly: true,
		Secure:   s.cfg.Cookie.Secure,
		SameSite: s.cfg.Cookie.SameSite,
	}
}

// Returns a cookie that removes the session cookie.
func (s *AuthService) clearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.Cookie.Name,
		Value:    "",
		Path:     s.cfg.Cookie.Path,
		Domain:   s.cfg.Cookie.Domain,
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Cookie.Secure,
		SameSite: s.cfg.Cookie.SameSite,
	}
}

// Returns the raw session token from the request cookie, or "" when it is absent.
func (s *AuthService) sessionTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(s.cfg.Cookie.Name)
	if err != nil {
		return ""
	}
	return cookie.Value
}
