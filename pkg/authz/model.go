package authz

import (
	"fmt"
	"os"
	"strings"
)

// Example authorization model for OpenFGA (DSL).
// Place this in your OpenFGA store when enabling OpenFGA.
const ModelDSL = `model
  schema 1.1

type user

type machine
  relations
    define viewer: [user]
    define can_access: viewer
`

// WriteExampleModel writes the example DSL to a path for operators.
func WriteExampleModel(path string) error {
	return os.WriteFile(path, []byte(strings.TrimSpace(ModelDSL)+"\n"), 0644)
}

// ErrNotConfigured is returned when OpenFGA is expected but missing.
var ErrNotConfigured = fmt.Errorf("openfga not configured")
