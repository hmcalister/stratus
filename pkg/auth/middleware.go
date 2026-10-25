package auth

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// The context key under which RequireAuth stores the authenticated identity.
type identityContextKey struct{}

// Returns the identity attached by RequireAuth.
//
// The second result is false when the request did not pass through RequireAuth.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

// Wraps next with session validation.
//
// Requests without a valid session receive 401 Unauthorized.
// Authenticated requests reach next with the identity available through IdentityFromContext.
//
// With the standard library mux:
//
//	mux.Handle("GET /private", service.RequireAuth(handler))
func (s *AuthService) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.sessionTokenFromRequest(r)
		identity, err := s.ValidateSession(r.Context(), token)
		if err != nil {
			if token != "" {
				http.SetCookie(w, s.clearSessionCookie())
			}
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Wraps a Huma operation with session validation.
//
// Requests without a valid session receive 401 Unauthorized.
// Authenticated requests reach the operation with the identity available through IdentityFromContext.
//
// Pass it in Operation.Middlewares:
//
//	huma.Register(api, huma.Operation{
//		Method:      http.MethodGet,
//		Path:        "/private",
//		Middlewares: huma.Middlewares{service.HumaRequireAuth},
//	}, handler)
func (s *AuthService) HumaRequireAuth(ctx huma.Context, next func(huma.Context)) {
	identity, err := s.ValidateSession(ctx.Context(), s.humaSessionToken(ctx.Header("Cookie")))
	if err != nil {
		ctx.SetStatus(http.StatusUnauthorized)
		return
	}

	next(huma.WithValue(ctx, identityContextKey{}, identity))
}
