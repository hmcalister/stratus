package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/hmcalister/stratus/pkg/sessionstore"
)

func TestCookieDefaults(t *testing.T) {
	ts := newTestService(t)
	config := ts.service.cfg.Cookie

	if config.Name != secureSessionCookieName {
		t.Errorf("Name = %q, want %q", config.Name, secureSessionCookieName)
	}
	if config.Path != "/" {
		t.Errorf("Path = %q, want %q", config.Path, "/")
	}
	if config.Domain != "" {
		t.Errorf("Domain = %q, want empty", config.Domain)
	}
	if !config.Secure {
		t.Error("Secure = false, want true for an https base url")
	}
	if config.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want SameSiteLaxMode", config.SameSite)
	}
}

func TestHTTPBaseURLUsesInsecureCookie(t *testing.T) {
	clock := newFakeClock()
	service, err := New(AuthServiceConfig{
		Sender:   &fakeSender{},
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "http://localhost:8080",
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cookie := service.sessionCookie("raw-token")
	if cookie.Name != insecureSessionCookieName {
		t.Errorf("Name = %q, want %q", cookie.Name, insecureSessionCookieName)
	}
	if cookie.Secure {
		t.Error("Secure = true, want false for an http base url")
	}
}

func TestSecureCanBeForcedForHTTPBaseURL(t *testing.T) {
	clock := newFakeClock()
	service, err := New(AuthServiceConfig{
		Sender:   &fakeSender{},
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "http://example.com",
		Cookie:   CookieConfig{Secure: true},
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cookie := service.sessionCookie("raw-token")
	if cookie.Name != secureSessionCookieName {
		t.Errorf("Name = %q, want %q", cookie.Name, secureSessionCookieName)
	}
	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	ts := newTestService(t)
	cookie := ts.service.sessionCookie("raw-token")

	if cookie.Name != secureSessionCookieName {
		t.Errorf("Name = %q, want %q", cookie.Name, secureSessionCookieName)
	}
	if cookie.Value != "raw-token" {
		t.Errorf("Value = %q, want %q", cookie.Value, "raw-token")
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want SameSiteLaxMode", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want %q", cookie.Path, "/")
	}
	if cookie.MaxAge != int(ts.service.cfg.SessionTTL/time.Second) {
		t.Errorf("MaxAge = %d, want %d", cookie.MaxAge, int(ts.service.cfg.SessionTTL/time.Second))
	}
	if !cookie.Expires.Equal(ts.clock.now().Add(ts.service.cfg.SessionTTL)) {
		t.Errorf("Expires = %v, want %v", cookie.Expires, ts.clock.now().Add(ts.service.cfg.SessionTTL))
	}
}

func TestSecureCookieUsesHostPrefix(t *testing.T) {
	clock := newFakeClock()
	service, err := New(AuthServiceConfig{
		Sender:   &fakeSender{},
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "https://example.com",
		Cookie:   CookieConfig{Secure: true},
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cookie := service.sessionCookie("raw-token")
	if cookie.Name != secureSessionCookieName {
		t.Errorf("Name = %q, want %q", cookie.Name, secureSessionCookieName)
	}
	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}
}

func TestCustomCookieNameIsPreserved(t *testing.T) {
	clock := newFakeClock()
	service, err := New(AuthServiceConfig{
		Sender:   &fakeSender{},
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "https://example.com",
		Cookie:   CookieConfig{Name: "my_session"},
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := service.cfg.Cookie.Name; got != "my_session" {
		t.Errorf("Name = %q, want %q", got, "my_session")
	}
}

func TestClearSessionCookie(t *testing.T) {
	ts := newTestService(t)
	cookie := ts.service.clearSessionCookie()

	if cookie.Name != ts.service.cfg.Cookie.Name {
		t.Errorf("Name = %q, want %q", cookie.Name, ts.service.cfg.Cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("Value = %q, want empty", cookie.Value)
	}
	if cookie.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want %q", cookie.Path, "/")
	}
}

func TestCookieConfigValidation(t *testing.T) {
	sender := &fakeSender{}
	store := sessionstore.NewMemorySessionStore()

	tests := []struct {
		name    string
		baseURL string
		cookie  CookieConfig
	}{
		{
			name:    "host prefix without secure",
			baseURL: "http://example.com",
			cookie:  CookieConfig{Name: "__Host-session"},
		},
		{
			name:    "host prefix with domain",
			baseURL: "https://example.com",
			cookie:  CookieConfig{Name: "__Host-session", Secure: true, Domain: "example.com"},
		},
		{
			name:    "host prefix with non-root path",
			baseURL: "https://example.com",
			cookie:  CookieConfig{Name: "__Host-session", Secure: true, Path: "/app"},
		},
		{
			name:    "invalid cookie name",
			baseURL: "https://example.com",
			cookie:  CookieConfig{Name: "bad name"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(AuthServiceConfig{
				Sender:   sender,
				Sessions: store,
				BaseURL:  test.baseURL,
				Cookie:   test.cookie,
			})
			if err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}
}
