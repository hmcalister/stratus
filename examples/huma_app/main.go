// A minimal example of wiring Stratus magic-link auth into a standard-library HTTP mux alongside a Huma v2 API.
//
// Stratus registers its routes as Huma operations, so they appear in the OpenAPI document that Huma builds. OpenAPI generation belongs to this consuming application. Stratus itself does not generate or ship a specification.
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

// A development-only dummy implementation of Sender.
type dummySender struct{}

func (dummySender) Send(_ context.Context, _ skysender.SendParams) error {
	return nil
}

// --------------------------------------------------------------------------------
// PRIVATE ROUTE PARAMS

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
	// Change these for your deployment.
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
