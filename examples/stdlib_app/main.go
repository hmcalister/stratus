// A minimal example of wiring Stratus magic-link auth into a standard-library HTTP mux.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/hmcalister/skysatchel/pkg/email/skysender"

	"github.com/hmcalister/stratus/pkg/auth"
	"github.com/hmcalister/stratus/pkg/sessionstore"
)

// A development-only dummy implementation of Sender.
type dummySender struct{}

func (dummySender) Send(_ context.Context, _ skysender.SendParams) error {
	return nil
}

func privateRouteHandleFunc(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	_, _ = fmt.Fprintf(w, "Signed in as %s\n", identity.Email)
}

func main() {
	const baseURL = "http://localhost:8080"
	const addr = ":8080"

	service, err := auth.New(auth.AuthServiceConfig{
		Sender:     dummySender{},
		Sessions:   sessionstore.NewMemorySessionStore(),
		BaseURL:    baseURL,
		SuccessURL: "/",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", service.Handlers())
	mux.Handle("GET /", service.RequireAuth(http.HandlerFunc(privateRouteHandleFunc)))

	log.Printf("listening on %s", baseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
