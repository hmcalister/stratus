# Stratus

Minimal email magic-link authentication for Go applications.

Stratus adds passwordless sign-in to an existing application. Your app just needs to construct an `auth.AuthService`, mounts its handlers, and wrap protected routes with `RequireAuth`. User profiles and their storage are left to the application to define, but may be indexed against `auth.Identity`. Sessions are stored in a `SessionStore` object, defaulting to an in-memory store (implementation provided).

Email is managed by [`github.com/hmcalister/skysatchel`](https://github.com/hmcalister/skysatchel), a simple interface for mailing. A generic SMTP sender implementation is provided in that project for quickstarts.

## Quick start

See the `examples` directory for a quick overview of Stratus offerings.

### StdLib

```go
package main

import (
	"log"
	"net/http"

	"github.com/hmcalister/stratus/pkg/auth"
	"github.com/hmcalister/stratus/pkg/sessionstore"
)

func main() {
	service, err := auth.New(auth.AuthServiceConfig{
		Sender:   sender, // any skysender.Sender
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "https://example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", service.AuthHandlers())
	mux.Handle("GET /", service.RequireAuth(http.HandlerFunc(private)))

	log.Printf("listening on %s", baseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func private(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Signed in as " + identity.Email))
}
```

### Huma

Applications that use [Huma](https://huma.rocks/) can register the auth routes as typed Huma operations with `RegisterHumaHandlers(api)`. The routes then appear in the OpenAPI document that the application generates, together with its own operations.

```go
mux := http.NewServeMux()
api := humago.New(mux, huma.DefaultConfig("My API", "1.0.0"))
RegisterHumaHandlers(api)
```

Stratus does not generate, write, or ship an OpenAPI specification. The consuming application exports the document that Huma built with `api.OpenAPI().YAML()`. See `examples/huma_app/generate_spec.go` for an example on how to do this.


```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/hmcalister/skysatchel/pkg/email/skysender"

	"github.com/hmcalister/stratus/pkg/auth"
	"github.com/hmcalister/stratus/pkg/sessionstore"
)

type PrivateRouteInput struct {
}

type PrivateRouteOutput struct {
	Body struct {
		Email string `json:"email" doc:"Email address of the signed-in user."`
	}
}

// Returns the signed-in user's identity. Requests without a valid session receive 401 Unauthorized.
func privateRouteHandleFunc(ctx context.Context, _ *PrivateRouteInput) (*PrivateRouteOutput, error) {
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		// This should never be reached if wrapped in auth middleware
		return nil, huma.Error401Unauthorized("a valid session is required")
	}

	out := &PrivateRouteOutput{}
	out.Body.Email = identity.Email
	return out, nil
}

func main() {
	service, err := auth.New(auth.AuthServiceConfig{
		Sender:   sender, // any skysender.Sender
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "https://example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Stratus example", "1.0.0"))

	// Register application routes
	huma.Register(api, huma.Operation{
		OperationID: "get-private",
		Method:      http.MethodGet,
		Path:        "/private",
		Summary:     "Protected endpoint",
		Middlewares: huma.Middlewares{service.HumaRequireAuth},
	}, privateRouteHandleFunc)

	// Register Auth routes
	service.RegisterHumaHandlers(api)

	log.Printf("listening on %s", baseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func private(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Signed in as " + identity.Email))
}
```

## HTTP routes

| Method | Path | Result |
| --- | --- | --- |
| `POST` | `/auth/magic-link` | Accepts a form or JSON `email` field. Always returns `202 Accepted` with the same body. |
| `GET` | `/auth/magic-link/consume?token=...` | Consumes the link, sets the session cookie, and redirects to `SuccessURL`. Invalid links get one neutral `400`. |
| `POST` | `/auth/logout` | Revokes the session in the store, clears the cookie, and returns `204 No Content`. |
| `POST` | `/auth/logout-all` | Revokes every session for the signed-in user, clears the cookie, and returns `204 No Content`. Requires a valid session. |

Other methods return `405 Method Not Allowed`.

## Configuration

### `auth.AuthServiceConfig`:

| Field | Default | Meaning |
| --- | --- | --- |
| `Sender` | required | A `skysender.Sender` that delivers the email. |
| `LinkEmail` | Subject `Sign in to <host>`, body `Click to sign in: <link>` | Builds the magic-link message. The message must include the link, or your users will be unable to sign in! |
| `Sessions` | required | A `sessionstore.SessionStore`. Use the provided `sessionstore.NewMemorySessionStore()` implementation for quickstart, in-process storage. |
| `BaseURL` | required | The public `http` or `https` origin. Magic links use this origin. |
| `LinkTTL` | `15m` | How long a magic link remains valid. |
| `SessionTTL` | `30 days` | How long a session remains valid. |
| `SuccessURL` | `/` | Redirect target after a successful consume. |
| `Cookie` | zero value | Session cookie settings. See below. |
| `RateLimit` | zero value | Token-bucket limits on link requests. See below. |
| `ClientIP` | `RemoteAddr` host | Returns the client IP address for rate limiting. Use `TrustedProxyClientIP` behind a reverse proxy. |
| `Now` | `time.Now` | Clock for tests. |

### `auth.CookieConfig`:

| Field | Default | Meaning |
| --- | --- | --- |
| `Name` | `__Host-stratus_session` on HTTPS, `stratus_session` otherwise | Cookie name. The `__Host-` prefix applies only when Secure is set, Path is `/`, and Domain is empty. |
| `Domain` | empty | Optional cookie domain. Empty makes a host-only cookie. |
| `Path` | `/` | Cookie path. |
| `Secure` | follows `BaseURL` | An `https` BaseURL sets Secure automatically. Set `true` to force Secure when `BaseURL` is `http` but TLS ends upstream. |
| `SameSite` | `Lax` | Cross-site sending policy. `Lax` keeps the post-consume redirect working. |

`HttpOnly` is always set.

### `auth.RateLimitConfig`:

| Field | Default | Meaning |
| --- | --- | --- |
| `EmailBurst` | `5` | Link requests one address may make immediately. |
| `EmailInterval` | `3m` | Time to restore one link request to an address's bucket. |
| `IPBurst` | `20` | Link requests one client IP may make immediately. |
| `IPInterval` | `45s` | Time to restore one link request to a client IP's bucket. |
| `Disabled` | `false` | Turns off link-request rate limiting entirely. |

A zero field keeps its default. Negative values make `auth.New` return an error.

### Customising the magic-link email

`LinkEmail` receives the sign-in link and returns the message to send:

```go
service, err := auth.New(auth.AuthServiceConfig{
	// ...
	LinkEmail: func(link string) skysatchel.Message {
		return skysatchel.Message{
			Subject: "Your example.com sign-in link",
			Body:    "Sign in here: " + link,
		}
	},
})
```

The message must contain the link, or the user cannot sign in.

### Client IP behind a proxy

By default the rate limiter uses the address of the direct network peer. Behind a reverse proxy, that address is the proxy. Pass a resolver:

```go
service, err := auth.New(auth.AuthServiceConfig{
	// ...
	ClientIP: auth.TrustedProxyClientIP([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}),
})
```

`TrustedProxyClientIP` reads `X-Forwarded-For` only when the immediate peer is inside the listed ranges. It reads the header from right to left, skips trusted proxies, and returns the first untrusted address. List only proxies that you control.

## Flow

1. `RequestLink` validates and normalises the address, applies rate limiting against address and IP, generates 32 random bytes and stores the SHA-256 hash with an expiry, then sends and email through the configured `skysender.Sender` with a message containing `{BaseURL}/auth/magic-link/consume?token=...`.
2. `ConsumeLink` hashes the presented token, removes it from its store if unexpired, generates a new 32-byte session token, stores `Session{TokenHash, Email, CreatedAt, ExpiresAt}`, and returns the identity and the raw session token. The user presents the session token as authentication in future requests.
    2a. The consume handler sets the session cookie and redirects to `SuccessURL`.
3. `RequireAuth` hashes the cookie value, loads the session, rejects it if expired, and attaches `Identity` to the request context.
4. `Logout` deletes the session row and clears the cookie. `LogoutAll` deletes every session for an address.

The service provides `RequestLink`, `ConsumeLink`, `ValidateSession`, `Logout`, and `LogoutAll` for applications that drive the flow without the built-in handlers.

### Rate limits

By default:

- One address: burst of 5 requests, then one request per 3 minutes.
- One client IP: burst of 20 requests, then one request per 45 seconds.

Override the defaults with `RateLimit`:

```go
service, err := auth.New(auth.AuthServiceConfig{
	// ...
	RateLimit: auth.RateLimitConfig{
		EmailBurst:    3,
		EmailInterval: 10 * time.Minute,
		IPBurst:       100,
		IPInterval:    10 * time.Second,
	},
})
```

Set `Disabled: true` to turn off link-request rate limiting, for example in tests. The per-IP limit applies only to the built-in HTTP and Huma handlers. `RequestLink` applies the per-address limit.

A request denied by either limit spends no token from the other.

## SessionStore

See `pkg/sessionstore/sessionstore.go` for the interface. The given implementation in `pkg/sessionstore/session_store_memory.go` uses in-memory storage. This may not scale well if you have a lot of concurrent users, instead consider implementing a new session store with a database table that indexes on email and expiry. For example, in Postgres:

```sql
CREATE TABLE auth_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    email      TEXT     NOT NULL,
    created_at BIGINT   NOT NULL,
    expires_at BIGINT   NOT NULL
);

CREATE INDEX auth_sessions_email_idx      ON auth_sessions (email);
CREATE INDEX auth_sessions_expires_at_idx ON auth_sessions (expires_at);
```

Notes for SQL implementations:

- `token_hash` is the hex SHA-256. It is always 64 characters.
- `Create` is an insert. Decide whether to replace or reject on a duplicate primary key. The interface allows replacement.
- `Get` selects by `token_hash`. `Delete` and `DeleteByEmail` delete by `token_hash` and `email`. `DeleteExpired` runs `DELETE ... WHERE expires_at <= ?`.
