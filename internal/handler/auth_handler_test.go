// internal/handler/auth_handler_test.go
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/httpvalidator"
	"bom-tanstack-api/internal/model"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeAuthServicer struct {
	loginAccess, loginRefresh string
	loginErr                  error
	meUser                    *model.User
	meErr                     error
	forgotErr                 error
	resetErr                  error
}

func (f *fakeAuthServicer) Login(ctx context.Context, email, password, userAgent string) (string, string, error) {
	return f.loginAccess, f.loginRefresh, f.loginErr
}
func (f *fakeAuthServicer) Refresh(ctx context.Context, refreshToken, userAgent string) (string, string, error) {
	return f.loginAccess, f.loginRefresh, f.loginErr
}
func (f *fakeAuthServicer) Logout(ctx context.Context, refreshToken string) error { return nil }
func (f *fakeAuthServicer) LogoutAll(ctx context.Context, userID primitive.ObjectID) error {
	return nil
}
func (f *fakeAuthServicer) ForgotPassword(ctx context.Context, email string) error {
	return f.forgotErr
}
func (f *fakeAuthServicer) ResetPassword(ctx context.Context, token, newPassword string) error {
	return f.resetErr
}
func (f *fakeAuthServicer) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error {
	return nil
}
func (f *fakeAuthServicer) Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	return f.meUser, f.meErr
}

func newTestEcho() *echo.Echo {
	e := echo.New()
	e.Validator = httpvalidator.New()
	return e
}

func TestAuthHandler_Login_Success(t *testing.T) {
	e := newTestEcho()
	svc := &fakeAuthServicer{loginAccess: "access-tok", loginRefresh: "refresh-tok"}
	h := NewAuthHandler(svc)
	body := strings.NewReader(`{"email":"alice@example.com","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Login(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "access-tok")
}

func TestAuthHandler_Login_ValidationFailureReturns400(t *testing.T) {
	e := newTestEcho()
	h := NewAuthHandler(&fakeAuthServicer{})
	body := strings.NewReader(`{"email":"not-an-email","password":""}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Login(c)

	assert.Error(t, err)
}

func TestAuthHandler_Login_InvalidCredentialsPropagatesDomainError(t *testing.T) {
	e := newTestEcho()
	svc := &fakeAuthServicer{loginErr: apperr.ErrInvalidCredentials}
	h := NewAuthHandler(svc)
	body := strings.NewReader(`{"email":"alice@example.com","password":"wrong"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Login(c)

	assert.ErrorIs(t, err, apperr.ErrInvalidCredentials)
}

func TestAuthHandler_Me_ReadsUserIDFromContext(t *testing.T) {
	e := newTestEcho()
	userID := primitive.NewObjectID()
	svc := &fakeAuthServicer{meUser: &model.User{ID: userID, Email: "alice@example.com"}}
	h := NewAuthHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", userID.Hex())

	err := h.Me(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "alice@example.com")
	assert.Contains(t, rec.Body.String(), "permissions")
}

func TestAuthHandler_Me_IncludesEffectivePermissionsForRole(t *testing.T) {
	e := newTestEcho()
	userID := primitive.NewObjectID()
	svc := &fakeAuthServicer{meUser: &model.User{ID: userID, Email: "admin@example.com", Role: "admin"}}
	h := NewAuthHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", userID.Hex())

	err := h.Me(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"user:create"`)
	assert.Contains(t, rec.Body.String(), `"user:read"`)
	assert.Contains(t, rec.Body.String(), `"user:update"`)
	assert.Contains(t, rec.Body.String(), `"user:delete"`)
}

func TestAuthHandler_ForgotPassword_AlwaysReturns200(t *testing.T) {
	e := newTestEcho()
	h := NewAuthHandler(&fakeAuthServicer{})
	body := strings.NewReader(`{"email":"nobody@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.ForgotPassword(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}
