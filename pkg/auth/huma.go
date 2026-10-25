package auth

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// The context key under which the per-request client IP is stored for Huma handlers.
// Huma typed handlers receive only a context.Context, so the request-link middleware computes the address and passes it through the context.
type clientIPContextKey struct{}

// Registers the magic-link routes with a Huma API:
//
//	POST /auth/magic-link
//	GET  /auth/magic-link/consume
//	POST /auth/logout
//	POST /auth/logout-all
//
// The paths are absolute and match the routes served by Handlers, so callers should mount one or the other, never both. This avoids duplicate route registration.
// Register is how the auth routes appear in the OpenAPI document that Huma generates for the consuming application. The library itself never writes a spec file.
//
// With the standard library mux and the humago adapter:
//
//	mux := http.NewServeMux()
//	api := humago.New(mux, huma.DefaultConfig("My API", "1.0.0"))
//	service.Register(api)
func (s *AuthService) Register(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "auth-request-link",
		Method:        http.MethodPost,
		Path:          magicLinkRequestPath,
		Tags:          []string{"auth"},
		Summary:       "Request a magic sign-in link",
		Description:   "Sends a single-use sign-in link to the given email address. The response is deliberately uniform so callers cannot probe address validity, rate limits, or delivery failures.",
		DefaultStatus: http.StatusAccepted,
		Middlewares:   huma.Middlewares{s.clientIPMiddleware},
	}, s.handleHumaRequestLink)

	huma.Register(api, huma.Operation{
		OperationID: "auth-consume-link",
		Method:      http.MethodGet,
		Path:        magicLinkConsumePath,
		Tags:        []string{"auth"},
		Summary:     "Consume a magic sign-in link",
		Description: "Exchanges a single-use magic-link token for a session cookie and redirects to the configured success URL. Unknown, expired, and used links share one neutral response.",
		// The token is documented as required, but parameter validation is skipped.
		// An absent or empty token reaches the handler and gets the same neutral 400 as any other invalid link, rather than a 422.
		SkipValidateParams: true,
		DefaultStatus:      http.StatusFound,
		Errors:             []int{http.StatusBadRequest},
	}, s.handleHumaConsumeLink)

	huma.Register(api, huma.Operation{
		OperationID:   "auth-logout",
		Method:        http.MethodPost,
		Path:          logoutPath,
		Tags:          []string{"auth"},
		Summary:       "Sign out",
		Description:   "Revokes the session carried by the session cookie and clears it. Calling it without a session is not an error.",
		DefaultStatus: http.StatusNoContent,
	}, s.handleHumaLogout)

	huma.Register(api, huma.Operation{
		OperationID:   "auth-logout-all",
		Method:        http.MethodPost,
		Path:          logoutAllPath,
		Tags:          []string{"auth"},
		Summary:       "Sign out of all devices",
		Description:   "Revokes every session belonging to the signed-in user and clears the session cookie. Requires a valid session.",
		DefaultStatus: http.StatusNoContent,
		Errors:        []int{http.StatusUnauthorized},
	}, s.handleHumaLogoutAll)
}

// Reconstructs the minimal request that the configured ClientIP function needs and stores the resulting address in the Huma context.
func (s *AuthService) clientIPMiddleware(ctx huma.Context, next func(huma.Context)) {
	r := &http.Request{
		RemoteAddr: ctx.RemoteAddr(),
		Header:     make(http.Header),
	}
	ctx.EachHeader(func(name, value string) {
		r.Header.Add(name, value)
	})

	next(huma.WithValue(ctx, clientIPContextKey{}, s.cfg.ClientIP(r)))
}

// --------------------------------------------------------------------------------
// REQUEST LINK

// The input body for the Huma request-link operation.
type requestLinkInput struct {
	Body struct {
		Email string `json:"email" required:"true" doc:"Address to send the sign-in link to."`
	}
}

// The output body for the Huma request-link operation. The status is always accepted.
type requestLinkOutput struct {
	Status int
	Body   struct {
		Status string `json:"status" doc:"Fixed accepted status."`
	}
}

// Handles the Huma request-link operation. The response never varies, so it does not act on the result of the request.
func (s *AuthService) handleHumaRequestLink(ctx context.Context, in *requestLinkInput) (*requestLinkOutput, error) {
	clientIP, _ := ctx.Value(clientIPContextKey{}).(string)

	// The response below never varies, so the result of the request is deliberately not acted on here.
	_ = s.requestLink(ctx, in.Body.Email, clientIP)

	out := &requestLinkOutput{Status: http.StatusAccepted}
	out.Body.Status = "accepted"
	return out, nil
}

// --------------------------------------------------------------------------------
// CONSUME LINK

// The input parameters for the Huma consume-link operation.
type consumeLinkInput struct {
	Token string `query:"token" required:"true" doc:"Single-use magic-link token."`
}

// The output headers for the Huma consume-link operation.
type consumeLinkOutput struct {
	Status       int
	Location     string   `header:"Location" doc:"Where to send the browser after sign-in."`
	SetCookie    []string `header:"Set-Cookie" doc:"Session cookie."`
	CacheControl string   `header:"Cache-Control" doc:"Prevents caching of the redirect."`
}

// Handles the Huma consume-link operation and returns a redirect to the success URL.
func (s *AuthService) handleHumaConsumeLink(ctx context.Context, in *consumeLinkInput) (*consumeLinkOutput, error) {
	_, sessionToken, err := s.ConsumeLink(ctx, in.Token)
	if err != nil {
		return nil, huma.Error400BadRequest("sign-in link is invalid or has expired")
	}

	return &consumeLinkOutput{
		Status:       http.StatusFound,
		Location:     s.cfg.SuccessURL,
		SetCookie:    []string{s.sessionCookie(sessionToken).String()},
		CacheControl: "no-store",
	}, nil
}

// --------------------------------------------------------------------------------
// LOGOUT LINK

// The input header for the Huma logout operation.
type logoutInput struct {
	Cookie string `header:"Cookie" doc:"Session cookie to revoke."`
}

// The output headers for the Huma logout operation.
type logoutOutput struct {
	Status    int
	SetCookie []string `header:"Set-Cookie" doc:"Clears the session cookie."`
}

// Handles the Huma logout operation and clears the session cookie.
func (s *AuthService) handleHumaLogout(ctx context.Context, in *logoutInput) (*logoutOutput, error) {
	if err := s.Logout(ctx, s.humaSessionToken(in.Cookie)); err != nil {
		return nil, huma.Error500InternalServerError("unable to sign out")
	}

	return &logoutOutput{
		Status:    http.StatusNoContent,
		SetCookie: []string{s.clearSessionCookie().String()},
	}, nil
}

// --------------------------------------------------------------------------------
// LOGOUT ALL LINK

// The input header for the logout-all operation.
type logoutAllInput struct {
	Cookie string `header:"Cookie" doc:"Session cookie identifying the user to sign out everywhere."`
}

// The output headers for the logout-all operation.
type logoutAllOutput struct {
	Status    int
	SetCookie []string `header:"Set-Cookie" doc:"Clears the session cookie."`
}

// Handles the logout-all operation and clears the session cookie.
func (s *AuthService) handleHumaLogoutAll(ctx context.Context, in *logoutAllInput) (*logoutAllOutput, error) {
	identity, err := s.ValidateSession(ctx, s.humaSessionToken(in.Cookie))
	if err != nil {
		return nil, huma.Error401Unauthorized("a valid session is required")
	}

	if err := s.LogoutAll(ctx, identity.Email); err != nil {
		return nil, huma.Error500InternalServerError("unable to sign out")
	}

	return &logoutAllOutput{
		Status:    http.StatusNoContent,
		SetCookie: []string{s.clearSessionCookie().String()},
	}, nil
}

// Returns the raw session token from a raw Cookie header, or "" when the header is absent, malformed, or carries no session cookie.
func (s *AuthService) humaSessionToken(cookieHeader string) string {
	if cookieHeader == "" {
		return ""
	}

	cookies, _ := http.ParseCookie(cookieHeader)
	for _, cookie := range cookies {
		if cookie.Name == s.cfg.Cookie.Name {
			return cookie.Value
		}
	}
	return ""
}
