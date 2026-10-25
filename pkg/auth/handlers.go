package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const (
	magicLinkRequestPath = "/auth/magic-link"
	magicLinkConsumePath = "/auth/magic-link/consume"
	logoutPath           = "/auth/logout"

	maxRequestBodyBytes = 1 << 20

	linkRequestResponseBody = "A sign-in link has been sent.\n"
)

// Returns a handler that serves the magic-link routes:
//
//	POST /auth/magic-link
//	GET  /auth/magic-link/consume
//	POST /auth/logout
//
// The routes are absolute, so mount the handler without stripping a prefix. With the standard library mux:
//
//	mux.Handle("/auth/", service.Handlers())
func (s *AuthService) Handlers() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+magicLinkRequestPath, s.handleRequestLink)
	mux.HandleFunc("GET "+magicLinkConsumePath, s.handleConsumeLink)
	mux.HandleFunc("POST "+logoutPath, s.handleLogout)
	return mux
}

// Accepts a form or JSON address and answers with the same response no matter what happens, so callers cannot probe address validity, rate limits, or delivery failures.
func (s *AuthService) handleRequestLink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	email, err := emailFromRequest(r)
	if err == nil {
		// The response below never varies, so the result of the request is deliberately not acted on here.
		_ = s.requestLink(r.Context(), email, s.cfg.ClientIP(r))
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	// The response is committed, so a write error cannot be reported to the client in any useful way.
	_, _ = io.WriteString(w, linkRequestResponseBody)
}

// Exchanges the link token for a session, sets the session cookie, and redirects to the success URL. Unknown, expired, and used links share one neutral response.
func (s *AuthService) handleConsumeLink(w http.ResponseWriter, r *http.Request) {
	_, sessionToken, err := s.ConsumeLink(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "sign-in link is invalid or has expired", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, s.sessionCookie(sessionToken))
	http.Redirect(w, r, s.cfg.SuccessURL, http.StatusFound)
}

// Revokes the session in the store and clears the cookie. It is safe to call without a session.
func (s *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.Logout(r.Context(), s.sessionTokenFromRequest(r)); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, s.clearSessionCookie())
	w.WriteHeader(http.StatusNoContent)
}

// Extracts the email field from a JSON or form-encoded body. An absent content type is treated as a form.
func emailFromRequest(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return formEmail(r)
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}

	switch mediaType {
	case "application/json":
		var payload struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return "", err
		}
		return payload.Email, nil
	case "application/x-www-form-urlencoded":
		return formEmail(r)
	default:
		return "", fmt.Errorf("unsupported content type %q", mediaType)
	}
}

// Returns the email field from a form-encoded body.
func formEmail(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return r.PostFormValue("email"), nil
}
