// internal/middleware/require_permission_test.go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirePermission_AllowsRoleWithPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("role", string(auth.RoleAdmin))

	handler := RequirePermission(auth.PermUserCreate)(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_BlocksRoleWithoutPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("role", string(auth.RoleStaff))

	handler := RequirePermission(auth.PermUserCreate)(func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	assert.ErrorIs(t, err, apperr.ErrPermissionDenied)
}
