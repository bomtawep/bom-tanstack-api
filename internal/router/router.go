// internal/router/router.go
package router

import (
	"net/http"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/handler"
	"bom-tanstack-api/internal/httpvalidator"
	appmiddleware "bom-tanstack-api/internal/middleware"

	"github.com/labstack/echo/v5"
)

func New(jwtSecret string, authHandler *handler.AuthHandler, userHandler *handler.UserHandler) *echo.Echo {
	e := echo.New()
	e.Validator = httpvalidator.New()
	e.HTTPErrorHandler = appmiddleware.ErrorHandler

	e.GET("/healthz", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	authGroup := e.Group("/api/v1/auth")
	authGroup.POST("/login", authHandler.Login)
	authGroup.POST("/refresh", authHandler.Refresh)
	authGroup.POST("/forgot-password", authHandler.ForgotPassword)
	authGroup.POST("/reset-password", authHandler.ResetPassword)

	jwtAuth := appmiddleware.JWTAuth(jwtSecret)
	authGroup.GET("/me", authHandler.Me, jwtAuth)
	authGroup.POST("/change-password", authHandler.ChangePassword, jwtAuth)
	authGroup.POST("/logout", authHandler.Logout, jwtAuth)
	authGroup.POST("/logout-all", authHandler.LogoutAll, jwtAuth)

	usersGroup := e.Group("/api/v1/users", jwtAuth)
	usersGroup.POST("", userHandler.Create, appmiddleware.RequirePermission(auth.PermUserCreate))
	usersGroup.GET("", userHandler.List, appmiddleware.RequirePermission(auth.PermUserRead))
	usersGroup.GET("/:id", userHandler.Get, appmiddleware.RequirePermission(auth.PermUserRead))
	usersGroup.PATCH("/:id", userHandler.Update, appmiddleware.RequirePermission(auth.PermUserUpdate))
	usersGroup.DELETE("/:id", userHandler.Delete, appmiddleware.RequirePermission(auth.PermUserDelete))

	return e
}
