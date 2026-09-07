// internal/middleware/jwt_auth_test.go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTAuth_ValidTokenSetsContextAndCallsNext(t *testing.T) {
	e := echo.New()
	token, err := auth.GenerateAccessToken("user-1", "admin", "secret", time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var gotUserID, gotRole string
	handler := JWTAuth("secret")(func(c *echo.Context) error {
		gotUserID = c.Get("userID").(string)
		gotRole = c.Get("role").(string)
		return c.NoContent(http.StatusOK)
	})

	err = handler(c)

	require.NoError(t, err)
	assert.Equal(t, "user-1", gotUserID)
	assert.Equal(t, "admin", gotRole)
}

func TestJWTAuth_MissingHeaderReturnsTokenInvalid(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth("secret")(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestJWTAuth_ExpiredTokenReturnsTokenExpired(t *testing.T) {
	e := echo.New()
	token, err := auth.GenerateAccessToken("user-1", "admin", "secret", -time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth("secret")(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err = handler(c)

	assert.ErrorIs(t, err, apperr.ErrTokenExpired)
}
