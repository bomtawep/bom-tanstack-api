// internal/handler/user_handler.go
package handler

import (
	"context"
	"net/http"
	"strconv"

	"bom-tanstack-api/internal/model"

	"github.com/labstack/echo/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type userServicer interface {
	CreateUser(ctx context.Context, email, name string, role string) (*model.User, error)
	ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error)
	GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error)
	UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error)
	DeactivateUser(ctx context.Context, id primitive.ObjectID) error
}

type UserHandler struct {
	service userServicer
}

func NewUserHandler(svc userServicer) *UserHandler {
	return &UserHandler{service: svc}
}

func paramObjectID(c *echo.Context) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Param("id"))
}

type createUserRequest struct {
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name" validate:"required"`
	Role  string `json:"role" validate:"required,oneof=admin manager staff viewer"`
}

func (h *UserHandler) Create(c *echo.Context) error {
	var req createUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	u, err := h.service.CreateUser(c.Request().Context(), req.Email, req.Name, req.Role)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, u)
}

func (h *UserHandler) List(c *echo.Context) error {
	limit, _ := strconv.ParseInt(c.QueryParam("limit"), 10, 64)
	skip, _ := strconv.ParseInt(c.QueryParam("skip"), 10, 64)

	users, err := h.service.ListUsers(c.Request().Context(), limit, skip)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, users)
}

func (h *UserHandler) Get(c *echo.Context) error {
	id, err := paramObjectID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}
	u, err := h.service.GetUser(c.Request().Context(), id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, u)
}

type updateUserRequest struct {
	Name  *string `json:"name" validate:"omitempty"`
	Email *string `json:"email" validate:"omitempty,email"`
	Role  *string `json:"role" validate:"omitempty,oneof=admin manager staff viewer"`
}

func (h *UserHandler) Update(c *echo.Context) error {
	id, err := paramObjectID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}
	var req updateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	u, err := h.service.UpdateUser(c.Request().Context(), id, req.Name, req.Email, req.Role)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, u)
}

func (h *UserHandler) Delete(c *echo.Context) error {
	id, err := paramObjectID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}
	if err := h.service.DeactivateUser(c.Request().Context(), id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
