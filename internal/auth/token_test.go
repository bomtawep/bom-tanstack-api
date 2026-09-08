// internal/auth/token_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomToken_ProducesUniqueValues(t *testing.T) {
	a, err := GenerateRandomToken()
	require.NoError(t, err)
	b, err := GenerateRandomToken()
	require.NoError(t, err)

	assert.Len(t, a, 64)
	assert.NotEqual(t, a, b)
}

func TestHashToken_IsDeterministicAndOneWay(t *testing.T) {
	raw := "some-raw-token-value"

	h1 := HashToken(raw)
	h2 := HashToken(raw)

	assert.Equal(t, h1, h2)
	assert.NotEqual(t, raw, h1)
}
