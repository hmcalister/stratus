package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	skysatchel "github.com/hmcalister/skysatchel/pkg/email"
	"github.com/hmcalister/skysatchel/pkg/email/skysender"

	"github.com/hmcalister/stratus/pkg/sessionstore"
)

type fakeSender struct {
	mu       sync.Mutex
	messages []skysender.SendParams
	err      error
}

func (s *fakeSender) Send(_ context.Context, params skysender.SendParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, params)
	return s.err
}

func (s *fakeSender) sent() []skysender.SendParams {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]skysender.SendParams(nil), s.messages...)
}

type testService struct {
	service *AuthService
	sender  *fakeSender
	clock   *fakeClock
	store   *sessionstore.MemorySessionStore
}

func newTestService(t *testing.T) *testService {
	t.Helper()
	return newTestServiceWithRateLimit(t, RateLimitConfig{})
}

func newTestServiceWithRateLimit(t *testing.T, rateLimit RateLimitConfig) *testService {
	t.Helper()

	clock := newFakeClock()
	sender := &fakeSender{}
	store := sessionstore.NewMemorySessionStore()

	service, err := New(AuthServiceConfig{
		Sender:    sender,
		Sessions:  store,
		BaseURL:   "https://example.com",
		RateLimit: rateLimit,
		Now:       clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &testService{service: service, sender: sender, clock: clock, store: store}
}

const testLinkPrefix = "Click to sign in: "

// Returns the raw token carried by a magic-link message.
func linkToken(t *testing.T, params skysender.SendParams) string {
	t.Helper()

	link, ok := strings.CutPrefix(params.Body, testLinkPrefix)
	if !ok {
		t.Fatalf("body = %q, want prefix %q", params.Body, testLinkPrefix)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("link %q has no token", link)
	}
	return token
}

// Requests a link for email and exchanges it for a session.
func requestAndConsume(t *testing.T, ts *testService, email string) (Identity, string) {
	t.Helper()

	if err := ts.service.RequestLink(t.Context(), email); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}

	messages := ts.sender.sent()
	token := linkToken(t, messages[len(messages)-1])

	identity, sessionToken, err := ts.service.ConsumeLink(t.Context(), token)
	if err != nil {
		t.Fatalf("ConsumeLink: %v", err)
	}
	return identity, sessionToken
}

func TestNewValidation(t *testing.T) {
	sender := &fakeSender{}
	store := sessionstore.NewMemorySessionStore()

	tests := []struct {
		name   string
		config AuthServiceConfig
	}{
		{
			name:   "missing sender",
			config: AuthServiceConfig{Sessions: store, BaseURL: "https://example.com"},
		},
		{
			name:   "missing sessions",
			config: AuthServiceConfig{Sender: sender, BaseURL: "https://example.com"},
		},
		{
			name:   "empty base url",
			config: AuthServiceConfig{Sender: sender, Sessions: store},
		},
		{
			name:   "base url without scheme",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "example.com"},
		},
		{
			name:   "unsupported scheme",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "ftp://example.com"},
		},
		{
			name:   "base url without host",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "https://"},
		},
		{
			name:   "base url with query",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "https://example.com?x=1"},
		},
		{
			name:   "negative link ttl",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "https://example.com", LinkTTL: -time.Second},
		},
		{
			name:   "negative session ttl",
			config: AuthServiceConfig{Sender: sender, Sessions: store, BaseURL: "https://example.com", SessionTTL: -time.Second},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.config); err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	ts := newTestService(t)

	if ts.service.cfg.LinkTTL != defaultLinkTTL {
		t.Errorf("LinkTTL = %v, want %v", ts.service.cfg.LinkTTL, defaultLinkTTL)
	}
	if ts.service.cfg.SessionTTL != defaultSessionTTL {
		t.Errorf("SessionTTL = %v, want %v", ts.service.cfg.SessionTTL, defaultSessionTTL)
	}
	if ts.service.cfg.SuccessURL != "/" {
		t.Errorf("SuccessURL = %q, want %q", ts.service.cfg.SuccessURL, "/")
	}
	if ts.service.cfg.Now == nil {
		t.Error("Now is nil, want a clock")
	}
	if ts.service.cfg.LinkEmail == nil {
		t.Error("LinkEmail is nil, want a composer")
	}
}

func TestRequestLinkSendsLinkToKnownAndUnknownAddresses(t *testing.T) {
	ts := newTestService(t)
	addresses := []string{"known@example.com", "unknown@example.com"}

	for _, address := range addresses {
		if err := ts.service.RequestLink(t.Context(), address); err != nil {
			t.Fatalf("RequestLink(%q): %v", address, err)
		}
	}

	messages := ts.sender.sent()
	if len(messages) != len(addresses) {
		t.Fatalf("%d messages sent, want %d", len(messages), len(addresses))
	}

	for i, address := range addresses {
		message := messages[i]
		if len(message.ToRecipients) != 1 || message.ToRecipients[0] != address {
			t.Errorf("recipients = %v, want [%s]", message.ToRecipients, address)
		}
		if message.Subject != "Sign in to example.com" {
			t.Errorf("subject = %q, want %q", message.Subject, "Sign in to example.com")
		}
		linkToken(t, message)
	}
}

func TestRequestLinkBuildsConsumeURL(t *testing.T) {
	ts := newTestService(t)

	if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}

	body := ts.sender.sent()[0].Body
	link, _ := strings.CutPrefix(body, testLinkPrefix)
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}

	if parsed.Scheme != "https" {
		t.Errorf("scheme = %q, want %q", parsed.Scheme, "https")
	}
	if parsed.Host != "example.com" {
		t.Errorf("host = %q, want %q", parsed.Host, "example.com")
	}
	if parsed.Path != magicLinkConsumePath {
		t.Errorf("path = %q, want %q", parsed.Path, magicLinkConsumePath)
	}
	// 32 random bytes, hex encoded.
	const wantTokenLength = 64
	if got := len(parsed.Query().Get("token")); got != wantTokenLength {
		t.Errorf("token length = %d, want %d", got, wantTokenLength)
	}
}

func TestRequestLinkNormalisesAddress(t *testing.T) {
	ts := newTestService(t)

	if err := ts.service.RequestLink(t.Context(), "  User+Tag@Example.COM  "); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}

	recipients := ts.sender.sent()[0].ToRecipients
	if len(recipients) != 1 || recipients[0] != "user@example.com" {
		t.Fatalf("recipients = %v, want [user@example.com]", recipients)
	}
}

func TestRequestLinkRejectsInvalidAddresses(t *testing.T) {
	ts := newTestService(t)

	tests := []string{
		"",
		"not an email",
		"two@example.com, three@example.com",
		"line@break\n.example.com",
	}

	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			err := ts.service.RequestLink(t.Context(), address)
			if !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("RequestLink(%q) error = %v, want ErrInvalidEmail", address, err)
			}
		})
	}

	if got := len(ts.sender.sent()); got != 0 {
		t.Fatalf("%d messages sent, want 0", got)
	}
}

func TestRequestLinkRateLimitsAddress(t *testing.T) {
	ts := newTestService(t)

	for i := range defaultEmailLinkBurst {
		if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}

	err := ts.service.RequestLink(t.Context(), "user@example.com")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("RequestLink error = %v, want ErrRateLimited", err)
	}
	if got := len(ts.sender.sent()); got != defaultEmailLinkBurst {
		t.Fatalf("%d messages sent, want %d", got, defaultEmailLinkBurst)
	}
}

func TestRateLimitDefaults(t *testing.T) {
	ts := newTestService(t)

	want := RateLimitConfig{
		EmailBurst:    defaultEmailLinkBurst,
		EmailInterval: defaultEmailLinkInterval,
		IPBurst:       defaultIPLinkBurst,
		IPInterval:    defaultIPLinkInterval,
	}
	if got := ts.service.cfg.RateLimit; got != want {
		t.Fatalf("RateLimit = %+v, want %+v", got, want)
	}
}

func TestRequestLinkUsesConfiguredRateLimit(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{
		EmailBurst:    2,
		EmailInterval: time.Minute,
	})

	for i := range 2 {
		if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}

	err := ts.service.RequestLink(t.Context(), "user@example.com")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("RequestLink error = %v, want ErrRateLimited", err)
	}

	ts.clock.advance(time.Minute)

	if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
		t.Fatalf("RequestLink after refill: %v", err)
	}
}

func TestRequestLinkAppliesConfiguredIPLimit(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{
		IPBurst:    1,
		IPInterval: time.Hour,
	})

	if err := ts.service.requestLink(t.Context(), "one@example.com", "203.0.113.7"); err != nil {
		t.Fatalf("first request: %v", err)
	}

	err := ts.service.requestLink(t.Context(), "two@example.com", "203.0.113.7")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second request error = %v, want ErrRateLimited", err)
	}
}

func TestRequestLinkRateLimitDisabled(t *testing.T) {
	ts := newTestServiceWithRateLimit(t, RateLimitConfig{Disabled: true})

	for i := range defaultEmailLinkBurst + 1 {
		if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
}

func TestNewRejectsNegativeRateLimits(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit RateLimitConfig
	}{
		{"email burst", RateLimitConfig{EmailBurst: -1}},
		{"email interval", RateLimitConfig{EmailInterval: -time.Second}},
		{"ip burst", RateLimitConfig{IPBurst: -1}},
		{"ip interval", RateLimitConfig{IPInterval: -time.Second}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(AuthServiceConfig{
				Sender:    &fakeSender{},
				Sessions:  sessionstore.NewMemorySessionStore(),
				BaseURL:   "https://example.com",
				RateLimit: test.rateLimit,
			})
			if err == nil {
				t.Fatal("New succeeded, want error")
			}
		})
	}
}

func TestRequestLinkPropagatesSendError(t *testing.T) {
	ts := newTestService(t)
	ts.sender.err = skysatchel.ErrDelivery

	err := ts.service.RequestLink(t.Context(), "user@example.com")
	if !errors.Is(err, skysatchel.ErrDelivery) {
		t.Fatalf("error = %v, want ErrDelivery", err)
	}
}
