// internal/auth/password_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_ProducesVerifiableHash(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "correct horse battery staple", hash)
}

func TestComparePassword_CorrectPasswordSucceeds(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)

	assert.True(t, ComparePassword(hash, "correct horse battery staple"))
}

func TestComparePassword_WrongPasswordFails(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)

	assert.False(t, ComparePassword(hash, "wrong password"))
}
