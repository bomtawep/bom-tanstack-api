// internal/handler/auth_handler.go
package handler

import (
	"context"
	"net/http"

	"bom-tanstack-api/internal/model"

	"github.com/labstack/echo/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type authServicer interface {
	Login(ctx context.Context, email, password, userAgent string) (string, string, error)
	Refresh(ctx context.Context, refreshToken, userAgent string) (string, string, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID primitive.ObjectID) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error
	Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error)
}

type AuthHandler struct {
	service authServicer
}

func NewAuthHandler(svc authServicer) *AuthHandler {
	return &AuthHandler{service: svc}
}

func contextUserID(c *echo.Context) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Get("userID").(string))
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (h *AuthHandler) Login(c *echo.Context) error {
	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	access, refresh, err := h.service.Login(c.Request().Context(), req.Email, req.Password, c.Request().UserAgent())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"accessToken": access, "refreshToken": refresh})
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

func (h *AuthHandler) Refresh(c *echo.Context) error {
	var req refreshRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	access, refresh, err := h.service.Refresh(c.Request().Context(), req.RefreshToken, c.Request().UserAgent())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"accessToken": access, "refreshToken": refresh})
}

func (h *AuthHandler) Logout(c *echo.Context) error {
	var req refreshRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := h.service.Logout(c.Request().Context(), req.RefreshToken); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) LogoutAll(c *echo.Context) error {
	userID, err := contextUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user context")
	}
	if err := h.service.LogoutAll(c.Request().Context(), userID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type forgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

func (h *AuthHandler) ForgotPassword(c *echo.Context) error {
	var req forgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := h.service.ForgotPassword(c.Request().Context(), req.Email); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "if that email exists, a reset link has been sent"})
}

type resetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

func (h *AuthHandler) ResetPassword(c *echo.Context) error {
	var req resetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := h.service.ResetPassword(c.Request().Context(), req.Token, req.NewPassword); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

func (h *AuthHandler) ChangePassword(c *echo.Context) error {
	userID, err := contextUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user context")
	}
	var req changePasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := h.service.ChangePassword(c.Request().Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) Me(c *echo.Context) error {
	userID, err := contextUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user context")
	}
	u, err := h.service.Me(c.Request().Context(), userID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, u)
}
