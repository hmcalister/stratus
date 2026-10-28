package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestHandlersRequestLinkFormAndJSON(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{
			name:        "form",
			body:        url.Values{"email": {"user@example.com"}}.Encode(),
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "json",
			body:        `{"email":"user@example.com"}`,
			contentType: "application/json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := newTestService(t)

			request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()

			ts.service.AuthHandlers().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
			}
			if got := recorder.Body.String(); got != linkRequestResponseBody {
				t.Fatalf("body = %q, want %q", got, linkRequestResponseBody)
			}

			messages := ts.sender.sent()
			if len(messages) != 1 {
				t.Fatalf("%d messages sent, want 1", len(messages))
			}
			if recipients := messages[0].ToRecipients; len(recipients) != 1 || recipients[0] != "user@example.com" {
				t.Fatalf("recipients = %v, want [user@example.com]", recipients)
			}
		})
	}
}

func TestHandlersRequestLinkResponseIsUniform(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		wantSent    int
	}{
		{
			name:        "valid known address",
			body:        url.Values{"email": {"user@example.com"}}.Encode(),
			contentType: "application/x-www-form-urlencoded",
			wantSent:    1,
		},
		{
			name:        "valid unknown address",
			body:        url.Values{"email": {"nobody@example.com"}}.Encode(),
			contentType: "application/x-www-form-urlencoded",
			wantSent:    1,
		},
		{
			name:        "invalid address",
			body:        url.Values{"email": {"not an email"}}.Encode(),
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "missing email",
			body:        `{}`,
			contentType: "application/json",
		},
		{
			name:        "malformed json",
			body:        `{`,
			contentType: "application/json",
		},
		{
			name:        "unsupported content type",
			body:        "user@example.com",
			contentType: "text/plain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := newTestService(t)

			request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()

			ts.service.AuthHandlers().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
			}
			if got := recorder.Body.String(); got != linkRequestResponseBody {
				t.Fatalf("body = %q, want %q", got, linkRequestResponseBody)
			}
			if got := len(ts.sender.sent()); got != test.wantSent {
				t.Fatalf("%d messages sent, want %d", got, test.wantSent)
			}
		})
	}
}

func TestHandlersRequestLinkRateLimitResponseIsUniform(t *testing.T) {
	ts := newTestService(t)
	handler := ts.service.AuthHandlers()
	body := url.Values{"email": {"user@example.com"}}.Encode()

	for i := range defaultEmailLinkBurst {
		request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("request %d: status = %d, want %d", i+1, recorder.Code, http.StatusAccepted)
		}
	}

	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("rate-limited status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	if got := recorder.Body.String(); got != linkRequestResponseBody {
		t.Fatalf("rate-limited body = %q, want %q", got, linkRequestResponseBody)
	}
	if got := len(ts.sender.sent()); got != defaultEmailLinkBurst {
		t.Fatalf("%d messages sent, want %d", got, defaultEmailLinkBurst)
	}
}

// Posts a form-encoded link request and returns the response recorder.
func postLinkForm(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestHandlersRevealRateLimitDenial(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{RevealDenials: true})
	handler := ts.service.AuthHandlers()
	body := url.Values{"email": {"user@example.com"}}.Encode()

	for i := range defaultEmailLinkBurst {
		if recorder := postLinkForm(handler, body); recorder.Code != http.StatusAccepted {
			t.Fatalf("request %d: status = %d, want %d", i+1, recorder.Code, http.StatusAccepted)
		}
	}

	recorder := postLinkForm(handler, body)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	// One token per interval, so the wait is that interval in whole seconds.
	wantRetryAfter := strconv.Itoa(int(defaultEmailLinkInterval.Seconds()))
	if got := recorder.Header().Get("Retry-After"); got != wantRetryAfter {
		t.Errorf("Retry-After = %q, want %q", got, wantRetryAfter)
	}
	if got := recorder.Body.String(); got != rateLimitResponseBody {
		t.Errorf("body = %q, want %q", got, rateLimitResponseBody)
	}
	if got := len(ts.sender.sent()); got != defaultEmailLinkBurst {
		t.Errorf("%d messages sent, want %d", got, defaultEmailLinkBurst)
	}
}

func TestHandlersRevealIPRateLimitDenial(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{
		IPBurst:       1,
		IPInterval:    time.Hour,
		RevealDenials: true,
	})
	handler := ts.service.AuthHandlers()

	if recorder := postLinkForm(handler, url.Values{"email": {"one@example.com"}}.Encode()); recorder.Code != http.StatusAccepted {
		t.Fatalf("first request status = %d, want %d", recorder.Code, http.StatusAccepted)
	}

	recorder := postLinkForm(handler, url.Values{"email": {"two@example.com"}}.Encode())
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if got, want := recorder.Header().Get("Retry-After"), "3600"; got != want {
		t.Errorf("Retry-After = %q, want %q", got, want)
	}
	// The body does not say which limit refused the request.
	if got := recorder.Body.String(); got != rateLimitResponseBody {
		t.Errorf("body = %q, want %q", got, rateLimitResponseBody)
	}
}

func TestHandlersRevealDenialsLeavesOtherResponsesUniform(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{RevealDenials: true})
	handler := ts.service.AuthHandlers()

	recorder := postLinkForm(handler, url.Values{"email": {"not an email"}}.Encode())
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	if got := recorder.Body.String(); got != linkRequestResponseBody {
		t.Fatalf("body = %q, want %q", got, linkRequestResponseBody)
	}
}

func TestHandlersConsumeLinkSetsCookieAndRedirects(t *testing.T) {
	ts := newTestService(t)
	if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}
	token := linkToken(t, ts.sender.sent()[0])

	request := httptest.NewRequest(http.MethodGet, magicLinkConsumePath+"?token="+url.QueryEscape(token), nil)
	recorder := httptest.NewRecorder()

	ts.service.AuthHandlers().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}
	if location := recorder.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want %q", location, "/")
	}

	cookie := findCookie(recorder.Result().Cookies(), ts.service.cfg.Cookie.Name)
	if cookie == nil {
		t.Fatal("session cookie was not set")
	}
	if cookie.Value == "" {
		t.Fatal("session cookie value is empty")
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

	if _, err := ts.service.ValidateSession(t.Context(), cookie.Value); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
}

func TestHandlersConsumeInvalidLinkIsNeutral(t *testing.T) {
	ts := newTestService(t)

	for _, token := range []string{"unknown", ""} {
		t.Run(token, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, magicLinkConsumePath+"?token="+url.QueryEscape(token), nil)
			recorder := httptest.NewRecorder()

			ts.service.AuthHandlers().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			if got := recorder.Body.String(); got != "sign-in link is invalid or has expired\n" {
				t.Fatalf("body = %q", got)
			}
			if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("%d cookies set, want 0", len(cookies))
			}
		})
	}
}

func TestHandlersLogoutClearsCookie(t *testing.T) {
	ts := newTestService(t)
	_, sessionToken := requestAndConsume(t, ts, "user@example.com")
	sessionCookie := ts.service.sessionCookie(sessionToken)

	request := httptest.NewRequest(http.MethodPost, logoutPath, nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()

	ts.service.AuthHandlers().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}

	cleared := findCookie(recorder.Result().Cookies(), ts.service.cfg.Cookie.Name)
	if cleared == nil {
		t.Fatal("clear cookie was not set")
	}
	if cleared.Value != "" {
		t.Errorf("cleared value = %q, want empty", cleared.Value)
	}
	if cleared.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative", cleared.MaxAge)
	}

	if _, err := ts.service.ValidateSession(t.Context(), sessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ValidateSession after Logout error = %v, want ErrUnauthenticated", err)
	}
}

func TestHandlersLogoutAllRevokesEverySession(t *testing.T) {
	ts := newTestService(t)
	_, firstToken := requestAndConsume(t, ts, "alice@example.com")
	_, secondToken := requestAndConsume(t, ts, "alice@example.com")
	_, bobToken := requestAndConsume(t, ts, "bob@example.com")

	request := httptest.NewRequest(http.MethodPost, logoutAllPath, nil)
	request.AddCookie(ts.service.sessionCookie(firstToken))
	recorder := httptest.NewRecorder()

	ts.service.AuthHandlers().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}

	cleared := findCookie(recorder.Result().Cookies(), ts.service.cfg.Cookie.Name)
	if cleared == nil {
		t.Fatal("clear cookie was not set")
	}
	if cleared.Value != "" {
		t.Errorf("cleared value = %q, want empty", cleared.Value)
	}

	for _, token := range []string{firstToken, secondToken} {
		if _, err := ts.service.ValidateSession(t.Context(), token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("ValidateSession after LogoutAll error = %v, want ErrUnauthenticated", err)
		}
	}
	if _, err := ts.service.ValidateSession(t.Context(), bobToken); err != nil {
		t.Fatalf("ValidateSession(bob) after LogoutAll: %v", err)
	}
}

func TestHandlersLogoutAllRequiresSession(t *testing.T) {
	ts := newTestService(t)
	_, sessionToken := requestAndConsume(t, ts, "user@example.com")

	tests := []struct {
		name   string
		cookie *http.Cookie
	}{
		{name: "no cookie"},
		{name: "unknown token", cookie: &http.Cookie{Name: ts.service.cfg.Cookie.Name, Value: strings.Repeat("a", 64)}},
		{name: "malformed token", cookie: &http.Cookie{Name: ts.service.cfg.Cookie.Name, Value: "unknown"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, logoutAllPath, nil)
			if test.cookie != nil {
				request.AddCookie(test.cookie)
			}
			recorder := httptest.NewRecorder()

			ts.service.AuthHandlers().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
			if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("%d cookies set, want 0", len(cookies))
			}
		})
	}

	if _, err := ts.service.ValidateSession(t.Context(), sessionToken); err != nil {
		t.Fatalf("ValidateSession after unauthorized LogoutAll: %v", err)
	}
}

func TestHandlersRejectWrongMethods(t *testing.T) {
	ts := newTestService(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "request link with GET", method: http.MethodGet, path: magicLinkRequestPath},
		{name: "consume with POST", method: http.MethodPost, path: magicLinkConsumePath},
		{name: "logout with GET", method: http.MethodGet, path: logoutPath},
		{name: "logout all with GET", method: http.MethodGet, path: logoutAllPath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			recorder := httptest.NewRecorder()

			ts.service.AuthHandlers().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestHandlersFullFlow(t *testing.T) {
	ts := newTestService(t)
	mux := http.NewServeMux()
	mux.Handle("/auth/", ts.service.AuthHandlers())

	var protectedIdentity Identity
	mux.Handle("GET /private", ts.service.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protectedIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})))

	// Request a link.
	form := url.Values{"email": {"user@example.com"}}
	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("request status = %d, want %d", recorder.Code, http.StatusAccepted)
	}

	messages := ts.sender.sent()
	if len(messages) != 1 {
		t.Fatalf("%d messages sent, want 1", len(messages))
	}
	token := linkToken(t, messages[0])

	// Consume the link.
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, magicLinkConsumePath+"?token="+url.QueryEscape(token), nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("consume status = %d, want %d", recorder.Code, http.StatusFound)
	}
	sessionCookie := findCookie(recorder.Result().Cookies(), ts.service.cfg.Cookie.Name)
	if sessionCookie == nil {
		t.Fatal("session cookie was not set")
	}

	// Reach the protected route.
	request = httptest.NewRequest(http.MethodGet, "/private", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if protectedIdentity.Email != "user@example.com" {
		t.Fatalf("protected identity = %+v, want user@example.com", protectedIdentity)
	}

	// Log out.
	request = httptest.NewRequest(http.MethodPost, logoutPath, nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", recorder.Code, http.StatusNoContent)
	}

	// The same cookie is now rejected.
	request = httptest.NewRequest(http.MethodGet, "/private", nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("after logout status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
