// internal/middleware/jwt_auth.go
package middleware

import (
	"strings"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
)

func JWTAuth(secret string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			header := c.Request().Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(header, prefix) {
				return apperr.ErrTokenInvalid
			}

			claims, err := auth.ParseAccessToken(strings.TrimPrefix(header, prefix), secret)
			if err != nil {
				return err
			}

			c.Set("userID", claims.UserID)
			c.Set("role", claims.Role)
			return next(c)
		}
	}
}
