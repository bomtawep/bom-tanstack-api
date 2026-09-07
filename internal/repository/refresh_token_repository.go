package repository

import (
	"context"
	"errors"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type RefreshTokenRepository struct {
	col *mongo.Collection
}

func NewRefreshTokenRepository(database *mongo.Database) *RefreshTokenRepository {
	return &RefreshTokenRepository{col: database.Collection("refresh_tokens")}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, rt *model.RefreshToken) error {
	_, err := r.col.InsertOne(ctx, rt)
	return err
}

func (r *RefreshTokenRepository) FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	var rt model.RefreshToken
	filter := bson.M{
		"token_hash": hash,
		"revoked_at": bson.M{"$exists": false},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}
	err := r.col.FindOne(ctx, filter).Decode(&rt)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, apperr.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, id primitive.ObjectID) error {
	now := time.Now().UTC()
	_, err := r.col.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"revoked_at": now}})
	return err
}

func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now().UTC()
	_, err := r.col.UpdateMany(ctx,
		bson.M{"user_id": userID, "revoked_at": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"revoked_at": now}},
	)
	return err
}
