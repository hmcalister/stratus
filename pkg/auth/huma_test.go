package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

// Builds a Huma API on the standard library mux and registers the auth routes with it.
func newHumaTestMux(t *testing.T) (*testService, http.Handler) {
	t.Helper()

	ts := newTestService(t)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	ts.service.HumaRegister(api)
	return ts, mux
}

func TestHumaRequestLinkAcceptsAndSends(t *testing.T) {
	ts, handler := newHumaTestMux(t)

	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(`{"email":"user@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", recorder.Body.String(), err)
	}
	if body.Status != "accepted" {
		t.Fatalf("body status = %q, want %q", body.Status, "accepted")
	}

	messages := ts.sender.sent()
	if len(messages) != 1 {
		t.Fatalf("%d messages sent, want 1", len(messages))
	}
	if recipients := messages[0].ToRecipients; len(recipients) != 1 || recipients[0] != "user@example.com" {
		t.Fatalf("recipients = %v, want [user@example.com]", recipients)
	}
}

func TestHumaRequestLinkMiddlewareReconstructsRequest(t *testing.T) {
	ts, handler := newHumaTestMux(t)

	var gotRemoteAddr, gotForwardedFor string
	ts.service.cfg.ClientIP = func(r *http.Request) string {
		gotRemoteAddr = r.RemoteAddr
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		return "203.0.113.9"
	}

	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(`{"email":"user@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.RemoteAddr = "198.51.100.7:4321"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusAccepted)
	}
	if gotRemoteAddr != "198.51.100.7:4321" {
		t.Errorf("ClientIP RemoteAddr = %q, want %q", gotRemoteAddr, "198.51.100.7:4321")
	}
	if gotForwardedFor != "203.0.113.9" {
		t.Errorf("ClientIP X-Forwarded-For = %q, want %q", gotForwardedFor, "203.0.113.9")
	}
}

func TestHumaFullFlow(t *testing.T) {
	ts, handler := newHumaTestMux(t)

	// Request a link.
	request := httptest.NewRequest(http.MethodPost, magicLinkRequestPath, strings.NewReader(`{"email":"user@example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
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
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, magicLinkConsumePath+"?token="+url.QueryEscape(token), nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("consume status = %d, want %d", recorder.Code, http.StatusFound)
	}
	if location := recorder.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want %q", location, "/")
	}
	if cacheControl := recorder.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", cacheControl, "no-store")
	}

	sessionCookie := findCookie(recorder.Result().Cookies(), ts.service.cfg.Cookie.Name)
	if sessionCookie == nil {
		t.Fatal("session cookie was not set")
	}
	if sessionCookie.Value == "" {
		t.Fatal("session cookie value is empty")
	}
	if _, err := ts.service.ValidateSession(t.Context(), sessionCookie.Value); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}

	// Log out using the raw cookie header.
	request = httptest.NewRequest(http.MethodPost, logoutPath, nil)
	request.AddCookie(sessionCookie)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", recorder.Code, http.StatusNoContent)
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

	if _, err := ts.service.ValidateSession(t.Context(), sessionCookie.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ValidateSession after logout error = %v, want ErrUnauthenticated", err)
	}
}

func TestHumaLogoutAllRevokesEverySession(t *testing.T) {
	ts, handler := newHumaTestMux(t)
	_, firstToken := requestAndConsume(t, ts, "alice@example.com")
	_, secondToken := requestAndConsume(t, ts, "alice@example.com")
	_, bobToken := requestAndConsume(t, ts, "bob@example.com")

	request := httptest.NewRequest(http.MethodPost, logoutAllPath, nil)
	request.AddCookie(ts.service.sessionCookie(firstToken))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

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

func TestHumaLogoutAllRequiresSession(t *testing.T) {
	ts, handler := newHumaTestMux(t)
	_, sessionToken := requestAndConsume(t, ts, "user@example.com")

	request := httptest.NewRequest(http.MethodPost, logoutAllPath, nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("%d cookies set, want 0", len(cookies))
	}
	if _, err := ts.service.ValidateSession(t.Context(), sessionToken); err != nil {
		t.Fatalf("ValidateSession after unauthorized LogoutAll: %v", err)
	}
}

func TestHumaConsumeInvalidLinkIsNeutral(t *testing.T) {
	_, handler := newHumaTestMux(t)

	tests := []string{
		"?token=unknown",
		"?token=",
		"",
	}

	for _, rawQuery := range tests {
		t.Run(rawQuery, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, magicLinkConsumePath+rawQuery, nil))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			if body := recorder.Body.String(); !strings.Contains(body, "sign-in link is invalid or has expired") {
				t.Fatalf("body = %q, want neutral error message", body)
			}
			if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("%d cookies set, want 0", len(cookies))
			}
		})
	}
}

func TestHumaOpenAPIDocumentsAuthRoutes(t *testing.T) {
	_, handler := newHumaTestMux(t)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	body := recorder.Body.String()
	for _, path := range []string{magicLinkRequestPath, magicLinkConsumePath, logoutPath, logoutAllPath} {
		if !strings.Contains(body, path) {
			t.Errorf("OpenAPI document does not contain path %q", path)
		}
	}

	// Parse the document as well, so that a path appearing only inside another
	// path or a description cannot make the substring checks above pass.
	type operation struct {
		OperationID string   `json:"operationId"`
		Tags        []string `json:"tags"`
	}
	var document struct {
		Paths map[string]struct {
			Get  *operation `json:"get"`
			Post *operation `json:"post"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode OpenAPI document: %v", err)
	}

	// Compare the final path segment as well, so "/auth/magic-link" cannot be
	// satisfied by the "/auth/magic-link/consume" entry alone.
	paths := make(map[string]bool, len(document.Paths))
	for path := range document.Paths {
		paths[path] = true
	}
	wantOperations := []struct {
		path, method, operationID string
	}{
		{magicLinkRequestPath, "Post", "auth-request-link"},
		{magicLinkConsumePath, "Get", "auth-consume-link"},
		{logoutPath, "Post", "auth-logout"},
		{logoutAllPath, "Post", "auth-logout-all"},
	}
	for _, want := range wantOperations {
		if !paths[want.path] {
			t.Errorf("OpenAPI document has no path %q", want.path)
			continue
		}
		item := document.Paths[want.path]
		var got *operation
		switch want.method {
		case "Get":
			got = item.Get
		case "Post":
			got = item.Post
		}
		if got == nil {
			t.Errorf("OpenAPI document has no %s operation for %q", want.method, want.path)
			continue
		}
		if got.OperationID != want.operationID {
			t.Errorf("%s %s operationId = %q, want %q", want.method, want.path, got.OperationID, want.operationID)
		}
		if len(got.Tags) != 1 || got.Tags[0] != "auth" {
			t.Errorf("%s %s tags = %v, want [auth]", want.method, want.path, got.Tags)
		}
	}
}
