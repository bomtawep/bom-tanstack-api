// internal/middleware/require_permission.go
package middleware

import (
	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
)

func RequirePermission(perm auth.Permission) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			role, _ := c.Get("role").(string)
			if !auth.HasPermission(auth.Role(role), perm) {
				return apperr.ErrPermissionDenied
			}
			return next(c)
		}
	}
}
