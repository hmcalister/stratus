package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	skysatchel "github.com/hmcalister/skysatchel/pkg/email"
	"github.com/hmcalister/skysatchel/pkg/email/skysender"
)

// Parses address and returns the normalised form used as the identity.
//
// Reports ErrInvalidEmail when the address cannot be parsed.
func normaliseEmail(address string) (string, error) {
	parsed, err := skysatchel.ParseAddress(strings.TrimSpace(address))
	if err != nil {
		return "", ErrInvalidEmail
	}

	normalised := skysatchel.NormalizeEmail(parsed)
	if normalised == "" {
		return "", ErrInvalidEmail
	}
	return normalised, nil
}

// Returns the URL that consumes token.
func (s *AuthService) magicLinkURL(token string) string {
	return strings.TrimRight(s.cfg.BaseURL, "/") + magicLinkConsumePath + "?token=" + url.QueryEscape(token)
}

// Returns the default magic-link composer, which names the application in the subject.
func defaultLinkEmail(appName string) func(address, link string) skysatchel.Message {
	return func(_, link string) skysatchel.Message {
		return skysatchel.Message{
			Subject: "Sign in to " + appName,
			Body:    "Click to sign in: " + link,
		}
	}
}

// Sends the magic-link email for address.
func (s *AuthService) sendLink(ctx context.Context, address, link string) error {
	err := s.cfg.Sender.Send(ctx, skysender.SendParams{
		Message:      s.cfg.LinkEmail(address, link),
		ToRecipients: []string{address},
	})
	if err != nil {
		return fmt.Errorf("send magic-link email: %w", err)
	}
	return nil
}
