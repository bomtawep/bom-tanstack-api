// internal/router/stubs_test.go
package router

import (
	"context"

	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type stubAuthServicer struct{}

func (s *stubAuthServicer) Login(ctx context.Context, email, password, userAgent string) (string, string, error) {
	return "access", "refresh", nil
}
func (s *stubAuthServicer) Refresh(ctx context.Context, refreshToken, userAgent string) (string, string, error) {
	return "access", "refresh", nil
}
func (s *stubAuthServicer) Logout(ctx context.Context, refreshToken string) error { return nil }
func (s *stubAuthServicer) LogoutAll(ctx context.Context, userID primitive.ObjectID) error {
	return nil
}
func (s *stubAuthServicer) ForgotPassword(ctx context.Context, email string) error { return nil }
func (s *stubAuthServicer) ResetPassword(ctx context.Context, token, newPassword string) error {
	return nil
}
func (s *stubAuthServicer) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error {
	return nil
}
func (s *stubAuthServicer) Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	return &model.User{ID: userID}, nil
}

type stubUserServicer struct{}

func (s *stubUserServicer) CreateUser(ctx context.Context, email, name, role string) (*model.User, error) {
	return &model.User{}, nil
}
func (s *stubUserServicer) ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	return nil, nil
}
func (s *stubUserServicer) GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	return &model.User{}, nil
}
func (s *stubUserServicer) UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error) {
	return &model.User{}, nil
}
func (s *stubUserServicer) DeactivateUser(ctx context.Context, id primitive.ObjectID) error {
	return nil
}
