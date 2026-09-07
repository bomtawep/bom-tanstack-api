// internal/handler/user_handler_test.go
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeUserServicer struct {
	createdUser *model.User
	createErr   error
	users       []*model.User
	getUser     *model.User
	getErr      error
}

func (f *fakeUserServicer) CreateUser(ctx context.Context, email, name string, role string) (*model.User, error) {
	return f.createdUser, f.createErr
}
func (f *fakeUserServicer) ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	return f.users, nil
}
func (f *fakeUserServicer) GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	return f.getUser, f.getErr
}
func (f *fakeUserServicer) UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error) {
	return f.getUser, f.getErr
}
func (f *fakeUserServicer) DeactivateUser(ctx context.Context, id primitive.ObjectID) error {
	return f.getErr
}

func TestUserHandler_Create_Success(t *testing.T) {
	e := newTestEcho()
	svc := &fakeUserServicer{createdUser: &model.User{Email: "new@example.com", Role: "staff"}}
	h := NewUserHandler(svc)
	body := strings.NewReader(`{"email":"new@example.com","name":"New Staff","role":"staff"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Create(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestUserHandler_Create_InvalidRoleFailsValidation(t *testing.T) {
	e := newTestEcho()
	h := NewUserHandler(&fakeUserServicer{})
	body := strings.NewReader(`{"email":"new@example.com","name":"New Staff","role":"superuser"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Create(c)

	assert.Error(t, err)
}

func TestUserHandler_Get_NotFoundPropagatesDomainError(t *testing.T) {
	e := newTestEcho()
	svc := &fakeUserServicer{getErr: apperr.ErrUserNotFound}
	h := NewUserHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	id := primitive.NewObjectID().Hex()
	c.SetPathValues(echo.PathValues{{Name: "id", Value: id}})

	err := h.Get(c)

	assert.ErrorIs(t, err, apperr.ErrUserNotFound)
}

func TestUserHandler_Delete_Success(t *testing.T) {
	e := newTestEcho()
	svc := &fakeUserServicer{}
	h := NewUserHandler(svc)
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	id := primitive.NewObjectID().Hex()
	c.SetPathValues(echo.PathValues{{Name: "id", Value: id}})

	err := h.Delete(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
