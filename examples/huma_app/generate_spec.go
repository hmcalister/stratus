//go:build ignore

// Generates the OpenAPI document for a Stratus auth service.
//
// Run it from this directory:
//
//	go run generate_spec.go > openapi.yaml
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/hmcalister/skysatchel/pkg/email/skysender"

	"github.com/hmcalister/stratus/pkg/auth"
	"github.com/hmcalister/stratus/pkg/sessionstore"
)

func main() {
	service, err := auth.New(auth.AuthServiceConfig{
		Sender:   skysender.NoOpSender{},
		Sessions: sessionstore.NewMemorySessionStore(),
		BaseURL:  "http://localhost:8080",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Stratus example", "1.0.0"))
	service.RegisterHumaHandlers(api)

	if err := dumpOpenAPI(api, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func dumpOpenAPI(api huma.API, w io.Writer) error {
	spec, err := api.OpenAPI().YAML()
	if err != nil {
		return fmt.Errorf("marshal OpenAPI document: %w", err)
	}
	if _, err := w.Write(spec); err != nil {
		return fmt.Errorf("write OpenAPI document: %w", err)
	}
	return nil
}
