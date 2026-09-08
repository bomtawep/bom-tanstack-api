// internal/auth/jwt_test.go
package auth

import (
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"

	"github.com/golang-jwt/jwt/v5"
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

func TestParseAccessToken_DifferentAlgorithmRejected(t *testing.T) {
	// Create a token signed with HS384 instead of HS256
	secret := "secret"
	claims := &Claims{
		UserID: "user-123",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	hs384Token, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	// Parsing should fail because the token uses HS384, not HS256
	_, err = ParseAccessToken(hs384Token, secret)

	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}
