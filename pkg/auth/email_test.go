package auth

import (
	"strings"
	"testing"

	skysatchel "github.com/hmcalister/skysatchel/pkg/email"

	"github.com/hmcalister/stratus/pkg/sessionstore"
)

func TestDefaultLinkEmail(t *testing.T) {
	ts := newTestService(t)
	if err := ts.service.RequestLink(t.Context(), "user@example.com"); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}

	messages := ts.sender.sent()
	if got, want := messages[0].Subject, "Sign in to example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}

	link := linkToken(t, messages[0])
	if got, want := messages[0].Body, "Click to sign in: "+ts.service.magicLinkURL(link); got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}

func TestLinkEmailIsConfigurable(t *testing.T) {
	sender := &fakeSender{}
	service, err := New(AuthServiceConfig{
		Sender:   sender,
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "https://example.com",
		LinkEmail: func(address, link string) skysatchel.Message {
			return skysatchel.Message{
				Subject: "Welcome to Acme, " + address,
				Body:    "Open this link: " + link,
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The composer receives the normalised address, not the raw input.
	if err := service.RequestLink(t.Context(), " User@Example.com "); err != nil {
		t.Fatalf("RequestLink: %v", err)
	}

	messages := sender.sent()
	if got, want := messages[0].Subject, "Welcome to Acme, user@example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}

	link, ok := strings.CutPrefix(messages[0].Body, "Open this link: ")
	if !ok {
		t.Fatalf("Body = %q, want prefix %q", messages[0].Body, "Open this link: ")
	}
	if want := "https://example.com/auth/magic-link/consume?token="; !strings.HasPrefix(link, want) {
		t.Errorf("link = %q, want prefix %q", link, want)
	}
}
