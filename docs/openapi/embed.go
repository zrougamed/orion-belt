// Package openapi embeds the Orion Belt OpenAPI 3.0 specification.
package openapi

import _ "embed"

// Spec is the OpenAPI 3.0 YAML document for the HTTP/WebSocket API.
//
//go:embed openapi.yaml
var Spec []byte
