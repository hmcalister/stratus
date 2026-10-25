package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	skysatchel "github.com/hmcalister/skysatchel/pkg/email"
	"github.com/hmcalister/skysatchel/pkg/email/skysender"

	"github.com/hmcalister/stratus/internal/linkstore"
	"github.com/hmcalister/stratus/internal/ratelimit"
	"github.com/hmcalister/stratus/internal/token"
	"github.com/hmcalister/stratus/pkg/sessionstore"
)

const (
	defaultLinkTTL    = 15 * time.Minute
	defaultSessionTTL = 30 * 24 * time.Hour
)

// Representative of an authenticated user.
//
// The identity is the normalised email address that the user signed in with.
// This is struct us what is consistent across sessions, and hence what should build an user table IDs.
type Identity struct {
	Email string
}

// Configures an AuthService.
//
// Sender, Sessions, and BaseURL are required. The remaining fields have defaults.
type AuthServiceConfig struct {
	// Delivers magic-link emails. Required.
	Sender skysender.Sender

	// Builds the magic-link email.
	//
	// The message must include link, or the user cannot sign in.
	// Defaults to a plain-text message with subject "Sign in to <host>" and body "Click to sign in: <link>".
	LinkEmail func(link string) skysatchel.Message

	// Persists issued sessions. Required.
	//
	// Use sessionstore.NewMemorySessionStore for in-memory storage.
	Sessions sessionstore.SessionStore

	// The public origin of the application. e.g. https://example.com.
	//
	// Magic links point at this origin.
	BaseURL string

	// How long a magic link remains valid.
	//
	// Defaults to 15 minutes.
	LinkTTL time.Duration

	// How long a session remains valid.
	//
	// Defaults to 30 days.
	SessionTTL time.Duration

	// Where the consume handler redirects after login.
	//
	// Defaults to "/".
	SuccessURL string

	// Configures the session cookie. HttpOnly is always set.
	//
	// The zero value uses Path "/", SameSite=Lax, and a Secure cookie whenever BaseURL uses https.
	Cookie CookieConfig

	// Configures per-address and per-client-IP limits on link requests.
	//
	// The zero value uses the defaults documented on RateLimitConfig.
	RateLimit RateLimitConfig

	// Returns the client address used to rate limit link requests.
	//
	// It defaults to the host part of http.Request.RemoteAddr.
	// Use TrustedProxyClientIP when the app runs behind a reverse proxy
	// (i.e. when http.Request.RemoteAddr is not the true client IP)
	ClientIP func(*http.Request) string

	// Returns the current time.
	// Defaults to time.Now and exists so tests can control time.
	// Do not set unless you have a very good reason.
	Now func() time.Time
}

// Issues magic links and manages the sessions that they create.
//
// Monolithic per application.
type AuthService struct {
	cfg     AuthServiceConfig
	appName string

	links   *linkstore.Store
	limiter *ratelimit.Limiter
}

// Validates cfg and returns an AuthService.
//
// Reports an error when a required field is missing or invalid.
func New(cfg AuthServiceConfig) (*AuthService, error) {
	if cfg.Sender == nil {
		return nil, errors.New("sender must be non-nil")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("sessions must be non-nil")
	}

	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, errors.New("base url must be non-empty")
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	if parsedBaseURL.Scheme != "http" && parsedBaseURL.Scheme != "https" {
		return nil, errors.New("base url scheme must be http or https")
	}
	if parsedBaseURL.Host == "" {
		return nil, errors.New("base url must include a host")
	}
	if parsedBaseURL.RawQuery != "" || parsedBaseURL.Fragment != "" {
		return nil, errors.New("base url must not include a query or fragment")
	}
	cfg.BaseURL = baseURL
	// An HTTPS public origin implies a Secure cookie, so production is secure by default.
	// An explicit Secure also covers apps served over HTTPS whose public origin is recorded as http because TLS terminates upstream.
	cfg.Cookie.Secure = cfg.Cookie.Secure || parsedBaseURL.Scheme == "https"

	if cfg.LinkTTL < 0 {
		return nil, errors.New("link ttl must not be negative")
	}
	if cfg.LinkTTL == 0 {
		cfg.LinkTTL = defaultLinkTTL
	}

	if cfg.SessionTTL < 0 {
		return nil, errors.New("session ttl must not be negative")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
	}

	if cfg.SuccessURL == "" {
		cfg.SuccessURL = "/"
	}

	cfg.Cookie = cfg.Cookie.withDefaultConfig()
	if err := cfg.Cookie.validate(); err != nil {
		return nil, err
	}

	if cfg.LinkEmail == nil {
		cfg.LinkEmail = defaultLinkEmail(parsedBaseURL.Host)
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = remoteAddrClientIP
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	rateLimit, err := cfg.RateLimit.withDefaults()
	if err != nil {
		return nil, err
	}
	cfg.RateLimit = rateLimit

	var limiter *ratelimit.Limiter
	if !rateLimit.Disabled {
		limiter = ratelimit.New(ratelimit.Config{
			EmailBurst:    rateLimit.EmailBurst,
			EmailInterval: rateLimit.EmailInterval,
			IPBurst:       rateLimit.IPBurst,
			IPInterval:    rateLimit.IPInterval,
			SweepCadence:  defaultLinkSweepCadence,
		}, cfg.Now)
	}

	return &AuthService{
		cfg:     cfg,
		appName: parsedBaseURL.Host,
		links:   linkstore.New(cfg.Now),
		limiter: limiter,
	}, nil
}

// Emails a single-use sign-in link to email. The email address is validated and normalised internally before use.
//
// Applies per-address rate limiting and returns ErrRateLimited when the address has requested too many links.
// The built-in HTTP handler also applies a per-client-IP limit. An invalid address returns ErrInvalidEmail.
func (s *AuthService) RequestLink(ctx context.Context, email string) error {
	return s.requestLink(ctx, email, "")
}

// Issues a link, applying the per-address limit and, when clientIP is non-empty, the per-client-IP limit.
func (s *AuthService) requestLink(ctx context.Context, email, clientIP string) error {
	address, err := normaliseEmail(email)
	if err != nil {
		return err
	}

	if s.limiter != nil && !s.limiter.Allow(address, clientIP) {
		return ErrRateLimited
	}

	rawToken, tokenHash, err := token.New()
	if err != nil {
		return fmt.Errorf("generate link token: %w", err)
	}

	s.links.Create(tokenHash, address, s.cfg.Now().Add(s.cfg.LinkTTL))

	if err := s.sendLink(ctx, address, s.magicLinkURL(rawToken)); err != nil {
		return err
	}
	return nil
}

// Exchanges a magic link for a session.
// Returns the identity and the raw session token, which the caller must put in a cookie.
// The link is removed whether or not it expired.
//
// Returns ErrInvalidLink when the token is unknown, expired, already used, or if the token is malformed.
func (s *AuthService) ConsumeLink(ctx context.Context, rawToken string) (Identity, string, error) {
	if !token.Valid(rawToken) {
		return Identity{}, "", ErrInvalidLink
	}

	address, ok := s.links.Consume(token.Hash(rawToken))
	if !ok {
		return Identity{}, "", ErrInvalidLink
	}

	rawSessionToken, sessionTokenHash, err := token.New()
	if err != nil {
		return Identity{}, "", fmt.Errorf("generate session token: %w", err)
	}

	now := s.cfg.Now()
	if err := s.cfg.Sessions.DeleteExpired(ctx, now); err != nil {
		return Identity{}, "", fmt.Errorf("delete expired sessions: %w", err)
	}

	session := sessionstore.Session{
		TokenHash: sessionTokenHash,
		Email:     address,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := s.cfg.Sessions.Create(ctx, session); err != nil {
		return Identity{}, "", fmt.Errorf("create session: %w", err)
	}

	return Identity{Email: address}, rawSessionToken, nil
}

// Returns the identity for a raw session token.
// Expired sessions are deleted when they are encountered.
//
// Returns ErrUnauthenticated when the token is empty, unknown, expired, or if the token is malformed.
func (s *AuthService) ValidateSession(ctx context.Context, rawToken string) (Identity, error) {
	if !token.Valid(rawToken) {
		return Identity{}, ErrUnauthenticated
	}

	session, err := s.cfg.Sessions.Get(ctx, token.Hash(rawToken))
	if errors.Is(err, sessionstore.ErrSessionNotFound) {
		return Identity{}, ErrUnauthenticated
	}
	if err != nil {
		return Identity{}, fmt.Errorf("get session: %w", err)
	}

	if !session.ExpiresAt.After(s.cfg.Now()) {
		if err := s.cfg.Sessions.Delete(ctx, session.TokenHash); err != nil {
			return Identity{}, fmt.Errorf("delete expired session: %w", err)
		}
		return Identity{}, ErrUnauthenticated
	}

	return Identity{Email: session.Email}, nil
}

// Deletes the session for token.
//
// Logging out an empty or unknown token is not an error.
// This prevents enumeration attacks.
func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	if !token.Valid(rawToken) {
		return nil
	}

	if err := s.cfg.Sessions.Delete(ctx, token.Hash(rawToken)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// Deletes every session belonging to email, which signs the user out on every device.
// The email address is validated and normalised internally before use.
func (s *AuthService) LogoutAll(ctx context.Context, email string) error {
	address, err := normaliseEmail(email)
	if err != nil {
		return err
	}

	if err := s.cfg.Sessions.DeleteByEmail(ctx, address); err != nil {
		return fmt.Errorf("delete sessions for address: %w", err)
	}
	return nil
}
