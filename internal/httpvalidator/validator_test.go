// internal/httpvalidator/validator_test.go
package httpvalidator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sampleRequest struct {
	Email string `validate:"required,email"`
}

func TestValidator_ValidStructPasses(t *testing.T) {
	v := New()

	err := v.Validate(&sampleRequest{Email: "user@example.com"})

	require.NoError(t, err)
}

func TestValidator_InvalidStructFails(t *testing.T) {
	v := New()

	err := v.Validate(&sampleRequest{Email: "not-an-email"})

	assert.Error(t, err)
}
