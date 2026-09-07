// internal/auth/jwt_test.go
package auth

import (
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndParseAccessToken_RoundTrips(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", time.Minute)
	require.NoError(t, err)

	claims, err := ParseAccessToken(token, "secret")

	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "admin", claims.Role)
}

func TestParseAccessToken_WrongSecretFails(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", time.Minute)
	require.NoError(t, err)

	_, err = ParseAccessToken(token, "wrong-secret")

	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestParseAccessToken_ExpiredFails(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", -time.Minute)
	require.NoError(t, err)

	_, err = ParseAccessToken(token, "secret")

	require.ErrorIs(t, err, apperr.ErrTokenExpired)
}
