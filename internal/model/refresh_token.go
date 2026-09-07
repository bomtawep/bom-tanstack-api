package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RefreshToken struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
	TokenHash string             `bson:"token_hash" json:"-"`
	UserAgent string             `bson:"user_agent" json:"userAgent"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"`
	RevokedAt *time.Time         `bson:"revoked_at,omitempty" json:"revokedAt,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
