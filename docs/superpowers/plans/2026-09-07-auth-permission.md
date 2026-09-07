# Auth + Permission (RBAC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational Auth + Permission (RBAC) module for `bom-tanstack-api`: JWT login/refresh, admin-managed users, fixed-role permission checks, and self-service password reset over MongoDB.

**Architecture:** Layered Echo service — `handler` (HTTP) → `service` (business logic, depends on narrow repository interfaces it defines itself) → `repository` (one struct per Mongo collection). Cross-cutting: `internal/auth` (JWT, bcrypt, permission map, random tokens), `internal/middleware` (JWTAuth, RequirePermission, centralized error mapping), `internal/mailer` (SMTP), `internal/apperr` (domain error sentinels).

**Tech Stack:** Go 1.27, Echo v5, MongoDB via `go.mongodb.org/mongo-driver`, `golang-jwt/jwt/v5`, `golang.org/x/crypto/bcrypt`, `go-playground/validator/v10`, `stretchr/testify`, `testcontainers-go` (Mongo module) for repository integration tests.

## Correction Log

- **Echo v5 `Context` is a struct, not an interface** (unlike v4). Every place below that reads `echo.Context` as a type must be `*echo.Context`: `echo.HandlerFunc = func(c *Context) error`, handler methods (`func (h *AuthHandler) Login(c *echo.Context) error`), etc. Discovered during Task 16; applies to Tasks 16-21.
- **`echo.HTTPErrorHandler`'s signature is `func(c *Context, err error)`** — context first, error second — not `func(err error, c echo.Context)` as written in Task 18 below. `middleware.ErrorHandler` must be `func ErrorHandler(c *echo.Context, err error)` with the body's error-handling logic unchanged, just the parameter order/type flipped.
- Everything else checked against the real `go.mongodb.org/mongo-driver`, `golang-jwt/jwt/v5`, and `echo/v5` sources during task reviews matched this plan's assumptions exactly (see individual task review notes in `.superpowers/sdd/progress.md`).

## Global Constraints

- Go module: `bom-tanstack-api`, Go 1.27.1 (from `go.mod`).
- Every persisted struct declares explicit `bson` and `json` tags (see `mongodb.md`).
- Every repository method takes `context.Context` as its first argument and passes it straight to the driver (see `mongodb.md`).
- Repository/service boundaries never leak `mongo.*` types or errors — only domain errors from `internal/apperr` (see `CLAUDE.md`, `mongodb.md`).
- No filter is ever built from raw string-concatenated user input (see `security.md`).
- List endpoints always cap page size server-side (see `mongodb.md`, `security.md`).
- Interfaces are declared in the consuming package, not the implementing one (see `CLAUDE.md`).
- Unit tests use `testify` (`assert`/`require`); integration tests against a real MongoDB run behind `//go:build integration` (see `testing.md`).
- Secrets (Mongo URI, JWT secret, SMTP creds, seed-admin password) load only from environment variables via `internal/config` — never hardcoded (see `security.md`).

---

## Task 1: Config loading

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config` struct (fields below) and `config.Load() (*Config, error)`, used by `cmd/api/main.go` (Task 21) and indirectly by every other task that needs a TTL/secret/URI.

```go
type Config struct {
    Port              string
    MongoURI          string
    MongoDBName       string
    JWTSecret         string
    AccessTokenTTL    time.Duration
    RefreshTokenTTL   time.Duration
    ResetTokenTTL     time.Duration
    SMTPHost          string
    SMTPPort          int
    SMTPUsername      string
    SMTPPassword      string
    SMTPFrom          string
    AppBaseURL        string
    SeedAdminEmail    string
    SeedAdminPassword string
}
```

Required env vars (error if missing/empty): `MONGO_URI`, `MONGO_DB_NAME`, `JWT_SECRET`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `APP_BASE_URL`.
Optional with defaults: `PORT` (default `8080`), `ACCESS_TOKEN_TTL` (default `15m`), `REFRESH_TOKEN_TTL` (default `720h`), `RESET_TOKEN_TTL` (default `30m`), `SMTP_USERNAME`, `SMTP_PASSWORD` (default `""`), `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD` (default `""`).

- [ ] **Step 1: Write the failing test**

```go
// internal/config/config_test.go
package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MONGO_URI", "mongodb://localhost:27017")
	t.Setenv("MONGO_DB_NAME", "bomtanstack")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "no-reply@example.com")
	t.Setenv("APP_BASE_URL", "https://app.example.com")
}

func TestLoad_DefaultsWhenOptionalUnset(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()

	require.NoError(t, err)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 720*time.Hour, cfg.RefreshTokenTTL)
	assert.Equal(t, 30*time.Minute, cfg.ResetTokenTTL)
	assert.Equal(t, "", cfg.SeedAdminEmail)
}

func TestLoad_MissingRequiredVarFails(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_SECRET", "")

	_, err := Load()

	require.Error(t, err)
}

func TestLoad_InvalidSMTPPortFails(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SMTP_PORT", "not-a-number")

	_, err := Load()

	require.Error(t, err)
}
```

Add `"time"` to the imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -v`
Expected: FAIL — `undefined: Load` (package doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port              string
	MongoURI          string
	MongoDBName       string
	JWTSecret         string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	ResetTokenTTL     time.Duration
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	AppBaseURL        string
	SeedAdminEmail    string
	SeedAdminPassword string
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:              getEnvDefault("PORT", "8080"),
		MongoURI:          os.Getenv("MONGO_URI"),
		MongoDBName:       os.Getenv("MONGO_DB_NAME"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		SMTPHost:          os.Getenv("SMTP_HOST"),
		SMTPUsername:      os.Getenv("SMTP_USERNAME"),
		SMTPPassword:      os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:          os.Getenv("SMTP_FROM"),
		AppBaseURL:        os.Getenv("APP_BASE_URL"),
		SeedAdminEmail:    os.Getenv("SEED_ADMIN_EMAIL"),
		SeedAdminPassword: os.Getenv("SEED_ADMIN_PASSWORD"),
	}

	for name, val := range map[string]string{
		"MONGO_URI":     cfg.MongoURI,
		"MONGO_DB_NAME": cfg.MongoDBName,
		"JWT_SECRET":    cfg.JWTSecret,
		"SMTP_HOST":     cfg.SMTPHost,
		"SMTP_FROM":     cfg.SMTPFrom,
		"APP_BASE_URL":  cfg.AppBaseURL,
	} {
		if val == "" {
			return nil, fmt.Errorf("config: required env var %s is not set", name)
		}
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		return nil, fmt.Errorf("config: invalid SMTP_PORT: %w", err)
	}
	cfg.SMTPPort = port

	cfg.AccessTokenTTL, err = parseDurationDefault("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.RefreshTokenTTL, err = parseDurationDefault("REFRESH_TOKEN_TTL", 720*time.Hour)
	if err != nil {
		return nil, err
	}
	cfg.ResetTokenTTL, err = parseDurationDefault("RESET_TOKEN_TTL", 30*time.Minute)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDurationDefault(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s: %w", key, err)
	}
	return d, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add env-based configuration loader"
```

---

## Task 2: Domain errors and models

**Files:**
- Create: `internal/apperr/errors.go`
- Create: `internal/model/user.go`
- Create: `internal/model/refresh_token.go`
- Create: `internal/model/password_reset_token.go`

**Interfaces:**
- Produces: sentinel errors `apperr.ErrUserNotFound`, `apperr.ErrInvalidCredentials`, `apperr.ErrUserInactive`, `apperr.ErrEmailAlreadyExists`, `apperr.ErrTokenInvalid`, `apperr.ErrTokenExpired`, `apperr.ErrPermissionDenied`; structs `model.User`, `model.RefreshToken`, `model.PasswordResetToken`. Used by every repository, service, and middleware task from here on.

These are pure declarations with no branching logic, so there is no behavior to drive with a failing test first — correctness is verified by the package compiling. Still commit them as their own reviewable unit.

- [ ] **Step 1: Write the domain error sentinels**

```go
// internal/apperr/errors.go
package apperr

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserInactive       = errors.New("user is inactive")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrTokenExpired       = errors.New("token expired")
	ErrPermissionDenied   = errors.New("permission denied")
)
```

- [ ] **Step 2: Write the models**

```go
// internal/model/user.go
package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id" json:"id"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Name         string             `bson:"name" json:"name"`
	Role         string             `bson:"role" json:"role"`
	Active       bool               `bson:"active" json:"active"`
	CreatedAt    time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updatedAt"`
}
```

```go
// internal/model/refresh_token.go
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
```

```go
// internal/model/password_reset_token.go
package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type PasswordResetToken struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
	TokenHash string             `bson:"token_hash" json:"-"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"`
	UsedAt    *time.Time         `bson:"used_at,omitempty" json:"usedAt,omitempty"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
```

- [ ] **Step 3: Add the Mongo driver dependency and verify the build**

Run: `go get go.mongodb.org/mongo-driver@latest`
Run: `go build ./...`
Expected: exits 0, no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/apperr internal/model go.mod go.sum
git commit -m "feat(model): add domain errors and User/RefreshToken/PasswordResetToken models"
```

---

## Task 3: Password hashing

**Files:**
- Create: `internal/auth/password.go`
- Test: `internal/auth/password_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `auth.HashPassword(plain string) (string, error)`, `auth.ComparePassword(hash, plain string) bool`. Used by `AuthService`/`UserService` (Tasks 13–14) and the seed-admin bootstrap (Task 15).

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/password_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_ProducesVerifiableHash(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "correct horse battery staple", hash)
}

func TestComparePassword_CorrectPasswordSucceeds(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)

	assert.True(t, ComparePassword(hash, "correct horse battery staple"))
}

func TestComparePassword_WrongPasswordFails(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)

	assert.False(t, ComparePassword(hash, "wrong password"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/... -v`
Expected: FAIL — `undefined: HashPassword`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/auth/password.go
package auth

import "golang.org/x/crypto/bcrypt"

func HashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func ComparePassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get golang.org/x/crypto@latest && go test ./internal/auth/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/auth/password.go internal/auth/password_test.go go.mod go.sum
git commit -m "feat(auth): add bcrypt password hashing"
```

---

## Task 4: Random tokens for refresh/reset

**Files:**
- Create: `internal/auth/token.go`
- Test: `internal/auth/token_test.go`

**Interfaces:**
- Produces: `auth.GenerateRandomToken() (string, error)` (64-char hex string), `auth.HashToken(raw string) string` (sha256 hex digest). Used by `AuthService` (Task 13), `UserService` (Task 14), and the shared reset-issuance helper (Task 12).

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/token_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomToken_ProducesUniqueValues(t *testing.T) {
	a, err := GenerateRandomToken()
	require.NoError(t, err)
	b, err := GenerateRandomToken()
	require.NoError(t, err)

	assert.Len(t, a, 64)
	assert.NotEqual(t, a, b)
}

func TestHashToken_IsDeterministicAndOneWay(t *testing.T) {
	raw := "some-raw-token-value"

	h1 := HashToken(raw)
	h2 := HashToken(raw)

	assert.Equal(t, h1, h2)
	assert.NotEqual(t, raw, h1)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/... -run TestGenerateRandomToken -v`
Expected: FAIL — `undefined: GenerateRandomToken`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/auth/token.go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func GenerateRandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/... -v`
Expected: PASS (all tests in the package, including Task 3's)

- [ ] **Step 5: Commit**

```bash
git add internal/auth/token.go internal/auth/token_test.go
git commit -m "feat(auth): add random token generation and hashing for refresh/reset tokens"
```

---

## Task 5: JWT access tokens

**Files:**
- Create: `internal/auth/jwt.go`
- Test: `internal/auth/jwt_test.go`

**Interfaces:**
- Consumes: `apperr.ErrTokenInvalid`, `apperr.ErrTokenExpired` (Task 2).
- Produces: `auth.Claims{UserID string; Role string; jwt.RegisteredClaims}`, `auth.GenerateAccessToken(userID, role, secret string, ttl time.Duration) (string, error)`, `auth.ParseAccessToken(tokenString, secret string) (*Claims, error)`. Used by `AuthService` (Task 13) and `JWTAuth` middleware (Task 16).

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/jwt_test.go
package auth

import (
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndParseAccessToken_RoundTrips(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", time.Minute)
	require.NoError(t, err)

	claims, err := ParseAccessToken(token, "secret")

	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "admin", claims.Role)
}

func TestParseAccessToken_WrongSecretFails(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", time.Minute)
	require.NoError(t, err)

	_, err = ParseAccessToken(token, "wrong-secret")

	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestParseAccessToken_ExpiredFails(t *testing.T) {
	token, err := GenerateAccessToken("user-123", "admin", "secret", -time.Minute)
	require.NoError(t, err)

	_, err = ParseAccessToken(token, "secret")

	require.ErrorIs(t, err, apperr.ErrTokenExpired)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/... -run TestGenerateAndParseAccessToken -v`
Expected: FAIL — `undefined: GenerateAccessToken`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/auth/jwt.go
package auth

import (
	"errors"
	"time"

	"bom-tanstack-api/internal/apperr"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID, role, secret string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ParseAccessToken(tokenString, secret string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, apperr.ErrTokenExpired
		}
		return nil, apperr.ErrTokenInvalid
	}
	return claims, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get github.com/golang-jwt/jwt/v5@latest && go test ./internal/auth/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/auth/jwt.go internal/auth/jwt_test.go go.mod go.sum
git commit -m "feat(auth): add JWT access token generation and parsing"
```

---

## Task 6: Permission map

**Files:**
- Create: `internal/auth/permissions.go`
- Test: `internal/auth/permissions_test.go`

**Interfaces:**
- Produces: `auth.Role` (string type, constants `RoleAdmin`, `RoleManager`, `RoleStaff`, `RoleViewer`), `auth.Permission` (string type, constants `PermUserCreate`, `PermUserRead`, `PermUserUpdate`, `PermUserDelete`), `auth.HasPermission(role Role, perm Permission) bool`. Used by `RequirePermission` middleware (Task 17), `UserService` (Task 14), and handlers validating role input (Task 20).

- [ ] **Step 1: Write the failing test**

```go
// internal/auth/permissions_test.go
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasPermission_AdminHasAllUserPermissions(t *testing.T) {
	for _, p := range []Permission{PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete} {
		assert.True(t, HasPermission(RoleAdmin, p), "admin should have %s", p)
	}
}

func TestHasPermission_ManagerOnlyHasRead(t *testing.T) {
	assert.True(t, HasPermission(RoleManager, PermUserRead))
	assert.False(t, HasPermission(RoleManager, PermUserCreate))
	assert.False(t, HasPermission(RoleManager, PermUserUpdate))
	assert.False(t, HasPermission(RoleManager, PermUserDelete))
}

func TestHasPermission_StaffAndViewerHaveNoUserPermissions(t *testing.T) {
	for _, role := range []Role{RoleStaff, RoleViewer} {
		for _, p := range []Permission{PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete} {
			assert.False(t, HasPermission(role, p), "%s should not have %s", role, p)
		}
	}
}

func TestHasPermission_UnknownRoleHasNoPermissions(t *testing.T) {
	assert.False(t, HasPermission(Role("nonexistent"), PermUserRead))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/... -run TestHasPermission -v`
Expected: FAIL — `undefined: RoleAdmin`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/auth/permissions.go
package auth

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleStaff   Role = "staff"
	RoleViewer  Role = "viewer"
)

type Permission string

const (
	PermUserCreate Permission = "user:create"
	PermUserRead   Permission = "user:read"
	PermUserUpdate Permission = "user:update"
	PermUserDelete Permission = "user:delete"
)

var rolePermissions = map[Role][]Permission{
	RoleAdmin:   {PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete},
	RoleManager: {PermUserRead},
	RoleStaff:   {},
	RoleViewer:  {},
}

func HasPermission(role Role, perm Permission) bool {
	for _, p := range rolePermissions[role] {
		if p == perm {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/auth/permissions.go internal/auth/permissions_test.go
git commit -m "feat(auth): add fixed role-to-permission map"
```

---

## Task 7: Mongo client and index setup

**Files:**
- Create: `internal/db/mongo.go`
- Test: `internal/db/mongo_test.go` (build tag `integration`)

**Interfaces:**
- Consumes: nothing from earlier tasks (models are referenced only by collection name strings).
- Produces: `db.Connect(ctx context.Context, uri string) (*mongo.Client, error)`, `db.EnsureIndexes(ctx context.Context, database *mongo.Database) error`. Used by `cmd/api/main.go` (Task 21) and every repository integration test (Tasks 8–10) to get a real `*mongo.Database`.

This task's test needs a running Docker daemon (testcontainers spins up a real `mongod`). All later integration tests reuse the same `testcontainers-go` mongodb module.

- [ ] **Step 1: Write the failing test**

```go
// internal/db/mongo_test.go
//go:build integration

package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
)

func TestEnsureIndexes_CreatesUniqueEmailIndex(t *testing.T) {
	ctx := context.Background()

	container, err := tcmongodb.Run(ctx, "mongo:7")
	require.NoError(t, err)
	defer container.Terminate(ctx)

	uri, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := Connect(ctx, uri)
	require.NoError(t, err)
	defer client.Disconnect(ctx)

	database := client.Database("testdb")
	require.NoError(t, EnsureIndexes(ctx, database))

	cursor, err := database.Collection("users").Indexes().List(ctx)
	require.NoError(t, err)
	var indexes []map[string]interface{}
	require.NoError(t, cursor.All(ctx, &indexes))

	found := false
	for _, idx := range indexes {
		if key, ok := idx["key"].(map[string]interface{}); ok {
			if _, hasEmail := key["email"]; hasEmail {
				found = true
				assert.Equal(t, true, idx["unique"])
			}
		}
	}
	assert.True(t, found, "expected a unique index on users.email")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/db/... -v`
Expected: FAIL — `undefined: Connect`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/db/mongo.go
package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func Connect(ctx context.Context, uri string) (*mongo.Client, error) {
	opts := options.Client().
		ApplyURI(uri).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second)

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, err
	}
	return client, nil
}

func EnsureIndexes(ctx context.Context, database *mongo.Database) error {
	if _, err := database.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}

	if _, err := database.Collection("refresh_tokens").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}); err != nil {
		return err
	}

	if _, err := database.Collection("password_reset_tokens").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}

	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get github.com/testcontainers/testcontainers-go/modules/mongodb@latest && go test -tags=integration ./internal/db/... -v`
Expected: PASS (requires Docker running locally/in CI)

- [ ] **Step 5: Commit**

```bash
git add internal/db go.mod go.sum
git commit -m "feat(db): add Mongo client connection and index setup"
```

---

## Task 8: UserRepository

**Files:**
- Create: `internal/repository/user_repository.go`
- Test: `internal/repository/user_repository_test.go` (build tag `integration`)

**Interfaces:**
- Consumes: `model.User` (Task 2), `apperr.ErrUserNotFound` / `apperr.ErrEmailAlreadyExists` (Task 2), `db.Connect`/`db.EnsureIndexes` (Task 7).
- Produces:
```go
type UserRepository struct{ /* unexported *mongo.Collection */ }
func NewUserRepository(database *mongo.Database) *UserRepository
func (r *UserRepository) Create(ctx context.Context, u *model.User) error
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error)
func (r *UserRepository) FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error)
func (r *UserRepository) List(ctx context.Context, limit, skip int64) ([]*model.User, error)
func (r *UserRepository) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error
func (r *UserRepository) ExistsActiveAdmin(ctx context.Context) (bool, error)
```
Used by `UserService` (Task 14), `AuthService` (Task 13), and `SeedAdmin` (Task 15).

- [ ] **Step 1: Write the failing test**

```go
// internal/repository/user_repository_test.go
//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/db"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func newTestDatabase(t *testing.T) *mongo.Database {
	t.Helper()
	ctx := context.Background()

	container, err := tcmongodb.Run(ctx, "mongo:7")
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(ctx) })

	uri, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := db.Connect(ctx, uri)
	require.NoError(t, err)
	t.Cleanup(func() { client.Disconnect(ctx) })

	database := client.Database("testdb")
	require.NoError(t, db.EnsureIndexes(ctx, database))
	return database
}

func newTestUser(email string) *model.User {
	now := time.Now().UTC()
	return &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: "hash",
		Name:         "Test User",
		Role:         "admin",
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestUserRepository_CreateAndFindByEmail(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	u := newTestUser("alice@example.com")

	require.NoError(t, repo.Create(ctx, u))

	found, err := repo.FindByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
}

func TestUserRepository_CreateDuplicateEmailFails(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newTestUser("bob@example.com")))

	err := repo.Create(ctx, newTestUser("bob@example.com"))

	require.ErrorIs(t, err, apperr.ErrEmailAlreadyExists)
}

func TestUserRepository_FindByEmailNotFoundReturnsDomainError(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))

	_, err := repo.FindByEmail(context.Background(), "nobody@example.com")

	require.ErrorIs(t, err, apperr.ErrUserNotFound)
}

func TestUserRepository_ExistsActiveAdmin(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()

	exists, err := repo.ExistsActiveAdmin(ctx)
	require.NoError(t, err)
	assert.False(t, exists)

	require.NoError(t, repo.Create(ctx, newTestUser("admin@example.com")))

	exists, err = repo.ExistsActiveAdmin(ctx)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestUserRepository_UpdateChangesFields(t *testing.T) {
	repo := NewUserRepository(newTestDatabase(t))
	ctx := context.Background()
	u := newTestUser("carol@example.com")
	require.NoError(t, repo.Create(ctx, u))

	require.NoError(t, repo.Update(ctx, u.ID, bson.M{"active": false}))

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, found.Active)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/repository/... -v`
Expected: FAIL — `undefined: NewUserRepository`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/repository/user_repository.go
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
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserRepository struct {
	col *mongo.Collection
}

func NewUserRepository(database *mongo.Database) *UserRepository {
	return &UserRepository{col: database.Collection("users")}
}

func (r *UserRepository) Create(ctx context.Context, u *model.User) error {
	_, err := r.col.InsertOne(ctx, u)
	if mongo.IsDuplicateKeyError(err) {
		return apperr.ErrEmailAlreadyExists
	}
	return err
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := r.col.FindOne(ctx, bson.M{"email": email}).Decode(&u)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, apperr.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	var u model.User
	err := r.col.FindOne(ctx, bson.M{"_id": id}).Decode(&u)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, apperr.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) List(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	opts := options.Find().SetLimit(limit).SetSkip(skip).SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*model.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *UserRepository) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = time.Now().UTC()
	res, err := r.col.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": update})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return apperr.ErrEmailAlreadyExists
		}
		return err
	}
	if res.MatchedCount == 0 {
		return apperr.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) ExistsActiveAdmin(ctx context.Context) (bool, error) {
	count, err := r.col.CountDocuments(ctx, bson.M{"role": "admin", "active": true})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/repository/... -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/user_repository.go internal/repository/user_repository_test.go
git commit -m "feat(repository): add UserRepository backed by MongoDB"
```

---

## Task 9: RefreshTokenRepository

**Files:**
- Create: `internal/repository/refresh_token_repository.go`
- Test: `internal/repository/refresh_token_repository_test.go` (build tag `integration`)

**Interfaces:**
- Consumes: `model.RefreshToken` (Task 2), `apperr.ErrTokenInvalid` (Task 2), `newTestDatabase` helper (Task 8, same package/file set).
- Produces:
```go
type RefreshTokenRepository struct{ /* unexported *mongo.Collection */ }
func NewRefreshTokenRepository(database *mongo.Database) *RefreshTokenRepository
func (r *RefreshTokenRepository) Create(ctx context.Context, rt *model.RefreshToken) error
func (r *RefreshTokenRepository) FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id primitive.ObjectID) error
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error
```
Used by `AuthService` (Task 13).

- [ ] **Step 1: Write the failing test**

```go
// internal/repository/refresh_token_repository_test.go
//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func newTestRefreshToken(userID primitive.ObjectID, hash string) *model.RefreshToken {
	now := time.Now().UTC()
	return &model.RefreshToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: hash,
		UserAgent: "test-agent",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
}

func TestRefreshTokenRepository_CreateAndFindActiveByHash(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	userID := primitive.NewObjectID()
	rt := newTestRefreshToken(userID, "hash-1")

	require.NoError(t, repo.Create(ctx, rt))

	found, err := repo.FindActiveByHash(ctx, "hash-1")
	require.NoError(t, err)
	assert.Equal(t, rt.ID, found.ID)
}

func TestRefreshTokenRepository_RevokedTokenNotFoundAsActive(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestRefreshToken(primitive.NewObjectID(), "hash-2")
	require.NoError(t, repo.Create(ctx, rt))

	require.NoError(t, repo.Revoke(ctx, rt.ID))

	_, err := repo.FindActiveByHash(ctx, "hash-2")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestRefreshTokenRepository_ExpiredTokenNotFoundAsActive(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestRefreshToken(primitive.NewObjectID(), "hash-3")
	rt.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	require.NoError(t, repo.Create(ctx, rt))

	_, err := repo.FindActiveByHash(ctx, "hash-3")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	repo := NewRefreshTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	userID := primitive.NewObjectID()
	require.NoError(t, repo.Create(ctx, newTestRefreshToken(userID, "hash-4")))
	require.NoError(t, repo.Create(ctx, newTestRefreshToken(userID, "hash-5")))

	require.NoError(t, repo.RevokeAllForUser(ctx, userID))

	_, err := repo.FindActiveByHash(ctx, "hash-4")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
	_, err = repo.FindActiveByHash(ctx, "hash-5")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/repository/... -run TestRefreshTokenRepository -v`
Expected: FAIL — `undefined: NewRefreshTokenRepository`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/repository/refresh_token_repository.go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/repository/... -v`
Expected: PASS (all tests in the package, including Task 8's)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/refresh_token_repository.go internal/repository/refresh_token_repository_test.go
git commit -m "feat(repository): add RefreshTokenRepository with rotation-friendly lookups"
```

---

## Task 10: PasswordResetTokenRepository

**Files:**
- Create: `internal/repository/password_reset_token_repository.go`
- Test: `internal/repository/password_reset_token_repository_test.go` (build tag `integration`)

**Interfaces:**
- Consumes: `model.PasswordResetToken` (Task 2), `apperr.ErrTokenInvalid` (Task 2), `newTestDatabase` helper (Task 8).
- Produces:
```go
type PasswordResetTokenRepository struct{ /* unexported *mongo.Collection */ }
func NewPasswordResetTokenRepository(database *mongo.Database) *PasswordResetTokenRepository
func (r *PasswordResetTokenRepository) Create(ctx context.Context, t *model.PasswordResetToken) error
func (r *PasswordResetTokenRepository) FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error)
func (r *PasswordResetTokenRepository) MarkUsed(ctx context.Context, id primitive.ObjectID) error
```
Used by the reset-issuance helper (Task 12) and `AuthService` (Task 13).

- [ ] **Step 1: Write the failing test**

```go
// internal/repository/password_reset_token_repository_test.go
//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func newTestResetToken(userID primitive.ObjectID, hash string) *model.PasswordResetToken {
	now := time.Now().UTC()
	return &model.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: now.Add(30 * time.Minute),
		CreatedAt: now,
	}
}

func TestPasswordResetTokenRepository_CreateAndFindActiveByHash(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-1")

	require.NoError(t, repo.Create(ctx, rt))

	found, err := repo.FindActiveByHash(ctx, "reset-hash-1")
	require.NoError(t, err)
	assert.Equal(t, rt.ID, found.ID)
}

func TestPasswordResetTokenRepository_UsedTokenNotFoundAsActive(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-2")
	require.NoError(t, repo.Create(ctx, rt))

	require.NoError(t, repo.MarkUsed(ctx, rt.ID))

	_, err := repo.FindActiveByHash(ctx, "reset-hash-2")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestPasswordResetTokenRepository_ExpiredTokenNotFoundAsActive(t *testing.T) {
	repo := NewPasswordResetTokenRepository(newTestDatabase(t))
	ctx := context.Background()
	rt := newTestResetToken(primitive.NewObjectID(), "reset-hash-3")
	rt.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, repo.Create(ctx, rt))

	_, err := repo.FindActiveByHash(ctx, "reset-hash-3")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/repository/... -run TestPasswordResetTokenRepository -v`
Expected: FAIL — `undefined: NewPasswordResetTokenRepository`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/repository/password_reset_token_repository.go
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

type PasswordResetTokenRepository struct {
	col *mongo.Collection
}

func NewPasswordResetTokenRepository(database *mongo.Database) *PasswordResetTokenRepository {
	return &PasswordResetTokenRepository{col: database.Collection("password_reset_tokens")}
}

func (r *PasswordResetTokenRepository) Create(ctx context.Context, t *model.PasswordResetToken) error {
	_, err := r.col.InsertOne(ctx, t)
	return err
}

func (r *PasswordResetTokenRepository) FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error) {
	var t model.PasswordResetToken
	filter := bson.M{
		"token_hash": hash,
		"used_at":    bson.M{"$exists": false},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}
	err := r.col.FindOne(ctx, filter).Decode(&t)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, apperr.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *PasswordResetTokenRepository) MarkUsed(ctx context.Context, id primitive.ObjectID) error {
	now := time.Now().UTC()
	_, err := r.col.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"used_at": now}})
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/repository/... -v`
Expected: PASS (all tests in the package, including Tasks 8–9's)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/password_reset_token_repository.go internal/repository/password_reset_token_repository_test.go
git commit -m "feat(repository): add PasswordResetTokenRepository"
```

---

## Task 11: Mailer

**Files:**
- Create: `internal/mailer/mailer.go`
- Create: `internal/mailer/smtp_mailer.go`
- Test: `internal/mailer/mailer_test.go`

**Interfaces:**
- Produces:
```go
type Mailer interface {
    Send(ctx context.Context, to, subject, body string) error
}
func BuildPasswordResetEmail(resetLink string) (subject, body string)
type SMTPMailer struct{ /* unexported host/port/username/password/from */ }
func NewSMTPMailer(host string, port int, username, password, from string) *SMTPMailer
func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error
```
Used by the reset-issuance helper (Task 12), `AuthService`/`UserService` (Tasks 13–14), and `cmd/api/main.go` (Task 21).

`BuildPasswordResetEmail` is pure and gets a real unit test. `SMTPMailer.Send` talks to a real network socket via `net/smtp`, so it is exercised manually/in a deployed environment rather than under `go test` — this matches `testing.md`'s rule against hitting real external services from unit tests.

- [ ] **Step 1: Write the failing test**

```go
// internal/mailer/mailer_test.go
package mailer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildPasswordResetEmail_IncludesLink(t *testing.T) {
	subject, body := BuildPasswordResetEmail("https://app.example.com/reset-password?token=abc123")

	assert.NotEmpty(t, subject)
	assert.Contains(t, body, "https://app.example.com/reset-password?token=abc123")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mailer/... -v`
Expected: FAIL — `undefined: BuildPasswordResetEmail`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/mailer/mailer.go
package mailer

import (
	"context"
	"fmt"
)

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

func BuildPasswordResetEmail(resetLink string) (subject, body string) {
	subject = "Reset your password"
	body = fmt.Sprintf(
		"We received a request to reset your password.\n\nClick the link below to choose a new one:\n%s\n\nIf you did not request this, you can ignore this email.",
		resetLink,
	)
	return subject, body
}
```

```go
// internal/mailer/smtp_mailer.go
package mailer

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPMailer struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func NewSMTPMailer(host string, port int, username, password, from string) *SMTPMailer {
	return &SMTPMailer{host: host, port: port, username: username, password: password, from: from}
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	msg := []byte("From: " + m.from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body + "\r\n")

	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}
	return smtp.SendMail(addr, auth, m.from, []string{to}, msg)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mailer/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mailer
git commit -m "feat(mailer): add SMTP mailer and password reset email template"
```

---

## Task 12: Shared password-reset issuance helper

**Files:**
- Create: `internal/service/reset_helper.go`
- Test: `internal/service/reset_helper_test.go`

**Interfaces:**
- Consumes: `auth.GenerateRandomToken`/`auth.HashToken` (Task 4), `model.PasswordResetToken` (Task 2), `mailer.Mailer`/`mailer.BuildPasswordResetEmail` (Task 11).
- Produces:
```go
type resetTokenRepository interface {
    Create(ctx context.Context, t *model.PasswordResetToken) error
}
func issuePasswordResetToken(ctx context.Context, repo resetTokenRepository, m mailer.Mailer, userID primitive.ObjectID, email string, ttl time.Duration, baseURL string) error
```
Used by `AuthService.ForgotPassword` and `UserService.CreateUser` (Tasks 13–14) so the "generate token, store hash, email raw link" logic is written once. `resetTokenRepository` is intentionally the minimal slice of `PasswordResetTokenRepository` (Task 10) this helper needs — per `CLAUDE.md`'s "interfaces in the consumer package" rule.

- [ ] **Step 1: Write the failing test**

```go
// internal/service/reset_helper_test.go
package service

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeResetTokenRepo struct {
	created *model.PasswordResetToken
}

func (f *fakeResetTokenRepo) Create(ctx context.Context, t *model.PasswordResetToken) error {
	f.created = t
	return nil
}

type fakeMailer struct {
	to, subject, body string
}

func (f *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	f.to, f.subject, f.body = to, subject, body
	return nil
}

func TestIssuePasswordResetToken_StoresHashAndEmailsRawToken(t *testing.T) {
	repo := &fakeResetTokenRepo{}
	m := &fakeMailer{}
	userID := primitive.NewObjectID()

	err := issuePasswordResetToken(context.Background(), repo, m, userID, "user@example.com", 30*time.Minute, "https://app.example.com")

	require.NoError(t, err)
	require.NotNil(t, repo.created)
	assert.Equal(t, userID, repo.created.UserID)
	assert.NotEmpty(t, repo.created.TokenHash)
	assert.Equal(t, "user@example.com", m.to)
	assert.Contains(t, m.body, "https://app.example.com/reset-password?token=")
	assert.NotContains(t, m.body, repo.created.TokenHash)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -v`
Expected: FAIL — `undefined: issuePasswordResetToken`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/service/reset_helper.go
package service

import (
	"context"
	"fmt"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type resetTokenRepository interface {
	Create(ctx context.Context, t *model.PasswordResetToken) error
}

func issuePasswordResetToken(
	ctx context.Context,
	repo resetTokenRepository,
	m mailer.Mailer,
	userID primitive.ObjectID,
	email string,
	ttl time.Duration,
	baseURL string,
) error {
	raw, err := auth.GenerateRandomToken()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	token := &model.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		TokenHash: auth.HashToken(raw),
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := repo.Create(ctx, token); err != nil {
		return err
	}

	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, raw)
	subject, body := mailer.BuildPasswordResetEmail(resetLink)
	return m.Send(ctx, email, subject, body)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/service/reset_helper.go internal/service/reset_helper_test.go
git commit -m "feat(service): add shared password-reset token issuance helper"
```

---

## Task 13: AuthService

**Files:**
- Create: `internal/service/auth_service.go`
- Test: `internal/service/auth_service_test.go`

**Interfaces:**
- Consumes: `model.User`/`model.RefreshToken` (Task 2), `apperr.*` (Task 2), `auth.ComparePassword`/`HashPassword` (Task 3), `auth.GenerateRandomToken`/`HashToken` (Task 4), `auth.GenerateAccessToken` (Task 5), `mailer.Mailer` (Task 11), `issuePasswordResetToken` + `resetTokenRepository` (Task 12).
- Produces:
```go
type AuthService struct{ /* unexported deps */ }
func NewAuthService(users userRepository, refreshTokens refreshTokenRepository, resetTokens passwordResetTokenRepository, m mailer.Mailer, jwtSecret string, accessTTL, refreshTTL, resetTTL time.Duration, baseURL string) *AuthService
func (s *AuthService) Login(ctx context.Context, email, password, userAgent string) (accessToken, refreshToken string, err error)
func (s *AuthService) Refresh(ctx context.Context, refreshToken, userAgent string) (accessToken, newRefreshToken string, err error)
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error
func (s *AuthService) LogoutAll(ctx context.Context, userID primitive.ObjectID) error
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error
func (s *AuthService) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error
func (s *AuthService) Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error)
```
The `userRepository`, `refreshTokenRepository`, and `passwordResetTokenRepository` interfaces declared here are the ones `*repository.UserRepository` (Task 8), `*repository.RefreshTokenRepository` (Task 9), and `*repository.PasswordResetTokenRepository` (Task 10) satisfy structurally. `AuthHandler` (Task 19) consumes this service through its own narrower interface.

- [ ] **Step 1: Write the failing test**

```go
// internal/service/auth_service_test.go
package service

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type fakeUserRepo struct {
	byEmail       map[string]*model.User
	byID          map[primitive.ObjectID]*model.User
	lastListLimit int64
	lastListSkip  int64
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byEmail: map[string]*model.User{}, byID: map[primitive.ObjectID]*model.User{}}
}

func (f *fakeUserRepo) add(u *model.User) {
	f.byEmail[u.Email] = u
	f.byID[u.ID] = u
}

func (f *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, apperr.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, apperr.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) Update(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	u, ok := f.byID[id]
	if !ok {
		return apperr.ErrUserNotFound
	}
	if v, ok := update["password_hash"].(string); ok {
		u.PasswordHash = v
	}
	if v, ok := update["active"].(bool); ok {
		u.Active = v
	}
	return nil
}

type fakeRefreshTokenRepo struct {
	byHash map[string]*model.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{byHash: map[string]*model.RefreshToken{}}
}

func (f *fakeRefreshTokenRepo) Create(ctx context.Context, rt *model.RefreshToken) error {
	f.byHash[rt.TokenHash] = rt
	return nil
}

func (f *fakeRefreshTokenRepo) FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	rt, ok := f.byHash[hash]
	if !ok || rt.RevokedAt != nil || rt.ExpiresAt.Before(time.Now()) {
		return nil, apperr.ErrTokenInvalid
	}
	return rt, nil
}

func (f *fakeRefreshTokenRepo) Revoke(ctx context.Context, id primitive.ObjectID) error {
	for _, rt := range f.byHash {
		if rt.ID == id {
			now := time.Now().UTC()
			rt.RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now().UTC()
	for _, rt := range f.byHash {
		if rt.UserID == userID {
			rt.RevokedAt = &now
		}
	}
	return nil
}

type fakeResetTokenRepoFull struct {
	byHash map[string]*model.PasswordResetToken
}

func newFakeResetTokenRepoFull() *fakeResetTokenRepoFull {
	return &fakeResetTokenRepoFull{byHash: map[string]*model.PasswordResetToken{}}
}

func (f *fakeResetTokenRepoFull) Create(ctx context.Context, t *model.PasswordResetToken) error {
	f.byHash[t.TokenHash] = t
	return nil
}

func (f *fakeResetTokenRepoFull) FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error) {
	t, ok := f.byHash[hash]
	if !ok || t.UsedAt != nil || t.ExpiresAt.Before(time.Now()) {
		return nil, apperr.ErrTokenInvalid
	}
	return t, nil
}

func (f *fakeResetTokenRepoFull) MarkUsed(ctx context.Context, id primitive.ObjectID) error {
	for _, t := range f.byHash {
		if t.ID == id {
			now := time.Now().UTC()
			t.UsedAt = &now
		}
	}
	return nil
}

func newTestAuthService(users *fakeUserRepo, refreshTokens *fakeRefreshTokenRepo, resetTokens *fakeResetTokenRepoFull, m *fakeMailer) *AuthService {
	return NewAuthService(users, refreshTokens, resetTokens, m, "test-secret", 15*time.Minute, 720*time.Hour, 30*time.Minute, "https://app.example.com")
}

func activeUser(email, password string) *model.User {
	hash, _ := auth.HashPassword(password)
	return &model.User{ID: primitive.NewObjectID(), Email: email, PasswordHash: hash, Role: "admin", Active: true}
}

func TestAuthService_Login_Success(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	access, refresh, err := svc.Login(context.Background(), "alice@example.com", "password123", "test-agent")

	require.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
}

func TestAuthService_Login_WrongPasswordFails(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("alice@example.com", "password123"))
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	_, _, err := svc.Login(context.Background(), "alice@example.com", "wrong-password", "test-agent")

	require.ErrorIs(t, err, apperr.ErrInvalidCredentials)
}

func TestAuthService_Login_InactiveUserFails(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	u.Active = false
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	_, _, err := svc.Login(context.Background(), "alice@example.com", "password123", "test-agent")

	require.ErrorIs(t, err, apperr.ErrUserInactive)
}

func TestAuthService_Refresh_RotatesTokenAndRejectsReuse(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("alice@example.com", "password123"))
	refreshTokens := newFakeRefreshTokenRepo()
	svc := newTestAuthService(users, refreshTokens, newFakeResetTokenRepoFull(), &fakeMailer{})
	_, firstRefresh, err := svc.Login(context.Background(), "alice@example.com", "password123", "agent-a")
	require.NoError(t, err)

	_, secondRefresh, err := svc.Refresh(context.Background(), firstRefresh, "agent-a")
	require.NoError(t, err)
	assert.NotEqual(t, firstRefresh, secondRefresh)

	_, _, err = svc.Refresh(context.Background(), firstRefresh, "agent-a")
	require.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestAuthService_ForgotPassword_UnknownEmailReturnsNilSilently(t *testing.T) {
	svc := newTestAuthService(newFakeUserRepo(), newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	err := svc.ForgotPassword(context.Background(), "nobody@example.com")

	require.NoError(t, err)
}

func TestAuthService_ResetPassword_RevokesAllSessions(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	refreshTokens := newFakeRefreshTokenRepo()
	resetTokens := newFakeResetTokenRepoFull()
	m := &fakeMailer{}
	svc := newTestAuthService(users, refreshTokens, resetTokens, m)
	_, refreshToken, err := svc.Login(context.Background(), "alice@example.com", "password123", "agent-a")
	require.NoError(t, err)
	require.NoError(t, svc.ForgotPassword(context.Background(), "alice@example.com"))

	rawResetToken := extractTokenFromLink(t, m.body)
	require.NoError(t, svc.ResetPassword(context.Background(), rawResetToken, "new-password-456"))

	_, _, err = svc.Refresh(context.Background(), refreshToken, "agent-a")
	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)

	_, _, err = svc.Login(context.Background(), "alice@example.com", "new-password-456", "agent-a")
	assert.NoError(t, err)
}

func TestAuthService_ChangePassword_WrongOldPasswordFails(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestAuthService(users, newFakeRefreshTokenRepo(), newFakeResetTokenRepoFull(), &fakeMailer{})

	err := svc.ChangePassword(context.Background(), u.ID, "wrong-old-password", "new-password-456")

	require.ErrorIs(t, err, apperr.ErrInvalidCredentials)
}
```

Add this helper, used only by `TestAuthService_ResetPassword_RevokesAllSessions`, to the same file:

```go
func extractTokenFromLink(t *testing.T, body string) string {
	t.Helper()
	const marker = "token="
	idx := indexOf(body, marker)
	require.GreaterOrEqual(t, idx, 0, "expected a reset link with a token in the email body")
	return body[idx+len(marker) : idx+len(marker)+64]
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -run TestAuthService -v`
Expected: FAIL — `undefined: NewAuthService`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/service/auth_service.go
package service

import (
	"context"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type userRepository interface {
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error)
	Update(ctx context.Context, id primitive.ObjectID, update bson.M) error
}

type refreshTokenRepository interface {
	Create(ctx context.Context, rt *model.RefreshToken) error
	FindActiveByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, id primitive.ObjectID) error
	RevokeAllForUser(ctx context.Context, userID primitive.ObjectID) error
}

type passwordResetTokenRepository interface {
	Create(ctx context.Context, t *model.PasswordResetToken) error
	FindActiveByHash(ctx context.Context, hash string) (*model.PasswordResetToken, error)
	MarkUsed(ctx context.Context, id primitive.ObjectID) error
}

type AuthService struct {
	users         userRepository
	refreshTokens refreshTokenRepository
	resetTokens   passwordResetTokenRepository
	mailer        mailer.Mailer
	jwtSecret     string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	resetTTL      time.Duration
	baseURL       string
}

func NewAuthService(
	users userRepository,
	refreshTokens refreshTokenRepository,
	resetTokens passwordResetTokenRepository,
	m mailer.Mailer,
	jwtSecret string,
	accessTTL, refreshTTL, resetTTL time.Duration,
	baseURL string,
) *AuthService {
	return &AuthService{
		users: users, refreshTokens: refreshTokens, resetTokens: resetTokens, mailer: m,
		jwtSecret: jwtSecret, accessTTL: accessTTL, refreshTTL: refreshTTL, resetTTL: resetTTL,
		baseURL: baseURL,
	}
}

func (s *AuthService) issueTokenPair(ctx context.Context, u *model.User, userAgent string) (string, string, error) {
	accessToken, err := auth.GenerateAccessToken(u.ID.Hex(), u.Role, s.jwtSecret, s.accessTTL)
	if err != nil {
		return "", "", err
	}

	raw, err := auth.GenerateRandomToken()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	rt := &model.RefreshToken{
		ID:        primitive.NewObjectID(),
		UserID:    u.ID,
		TokenHash: auth.HashToken(raw),
		UserAgent: userAgent,
		ExpiresAt: now.Add(s.refreshTTL),
		CreatedAt: now,
	}
	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return "", "", err
	}
	return accessToken, raw, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent string) (string, string, error) {
	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return "", "", apperr.ErrInvalidCredentials
	}
	if !u.Active {
		return "", "", apperr.ErrUserInactive
	}
	if !auth.ComparePassword(u.PasswordHash, password) {
		return "", "", apperr.ErrInvalidCredentials
	}
	return s.issueTokenPair(ctx, u, userAgent)
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken, userAgent string) (string, string, error) {
	hash := auth.HashToken(refreshToken)
	rt, err := s.refreshTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return "", "", err
	}
	if err := s.refreshTokens.Revoke(ctx, rt.ID); err != nil {
		return "", "", err
	}

	u, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil {
		return "", "", err
	}
	if !u.Active {
		return "", "", apperr.ErrUserInactive
	}
	return s.issueTokenPair(ctx, u, userAgent)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := auth.HashToken(refreshToken)
	rt, err := s.refreshTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return nil
	}
	return s.refreshTokens.Revoke(ctx, rt.ID)
}

func (s *AuthService) LogoutAll(ctx context.Context, userID primitive.ObjectID) error {
	return s.refreshTokens.RevokeAllForUser(ctx, userID)
}

func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil
	}
	if !u.Active {
		return nil
	}
	return issuePasswordResetToken(ctx, s.resetTokens, s.mailer, u.ID, u.Email, s.resetTTL, s.baseURL)
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	hash := auth.HashToken(token)
	rt, err := s.resetTokens.FindActiveByHash(ctx, hash)
	if err != nil {
		return err
	}

	hashedPW, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.Update(ctx, rt.UserID, bson.M{"password_hash": hashedPW}); err != nil {
		return err
	}
	if err := s.resetTokens.MarkUsed(ctx, rt.ID); err != nil {
		return err
	}
	return s.refreshTokens.RevokeAllForUser(ctx, rt.UserID)
}

func (s *AuthService) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if !auth.ComparePassword(u.PasswordHash, oldPassword) {
		return apperr.ErrInvalidCredentials
	}
	hashedPW, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.users.Update(ctx, userID, bson.M{"password_hash": hashedPW})
}

func (s *AuthService) Me(ctx context.Context, userID primitive.ObjectID) (*model.User, error) {
	return s.users.FindByID(ctx, userID)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v`
Expected: PASS (all tests in the package, including Task 12's)

- [ ] **Step 5: Commit**

```bash
git add internal/service/auth_service.go internal/service/auth_service_test.go
git commit -m "feat(service): add AuthService with login, refresh rotation, and password reset"
```

---

## Task 14: UserService

**Files:**
- Create: `internal/service/user_service.go`
- Create: `internal/service/user_service_test.go`
- Modify: `internal/service/auth_service_test.go` (already updated in Task 13 with `lastListLimit`/`lastListSkip` fields on `fakeUserRepo`)

**Interfaces:**
- Consumes: `model.User` (Task 2), `apperr.ErrEmailAlreadyExists` (Task 2), `auth.Role`, `auth.GenerateRandomToken`/`HashPassword` (Tasks 3–4, 6), `mailer.Mailer` (Task 11), `resetTokenRepository` + `issuePasswordResetToken` (Task 12).
- Produces:
```go
type UserService struct{ /* unexported deps */ }
func NewUserService(users userManagementRepository, resetTokens resetTokenRepository, m mailer.Mailer, resetTTL time.Duration, baseURL string) *UserService
func (s *UserService) CreateUser(ctx context.Context, email, name, role string) (*model.User, error)
func (s *UserService) ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error)
func (s *UserService) GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error)
func (s *UserService) UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error)
func (s *UserService) DeactivateUser(ctx context.Context, id primitive.ObjectID) error
```
`UserHandler` (Task 20) consumes this through its own narrower interface. `ListUsers` caps `limit` server-side per `mongodb.md`/`security.md` regardless of what the caller requests.

- [ ] **Step 1: Write the failing test**

```go
// internal/service/user_service_test.go
package service

import (
	"context"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *fakeUserRepo) Create(ctx context.Context, u *model.User) error {
	if _, exists := f.byEmail[u.Email]; exists {
		return apperr.ErrEmailAlreadyExists
	}
	f.add(u)
	return nil
}

func (f *fakeUserRepo) List(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	f.lastListLimit = limit
	f.lastListSkip = skip
	var out []*model.User
	for _, u := range f.byID {
		out = append(out, u)
	}
	if int64(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

func newTestUserService(users *fakeUserRepo, resetTokens *fakeResetTokenRepoFull, m *fakeMailer) *UserService {
	return NewUserService(users, resetTokens, m, 30*time.Minute, "https://app.example.com")
}

func TestUserService_CreateUser_SendsResetEmailAndNoUsablePasswordIsReturned(t *testing.T) {
	users := newFakeUserRepo()
	m := &fakeMailer{}
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), m)

	u, err := svc.CreateUser(context.Background(), "newstaff@example.com", "New Staff", "staff")

	require.NoError(t, err)
	assert.Equal(t, "newstaff@example.com", m.to)
	assert.NotEmpty(t, u.PasswordHash)
	assert.False(t, auth.ComparePassword(u.PasswordHash, ""))
}

func TestUserService_CreateUser_DuplicateEmailFails(t *testing.T) {
	users := newFakeUserRepo()
	users.add(activeUser("existing@example.com", "irrelevant"))
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.CreateUser(context.Background(), "existing@example.com", "Someone", "staff")

	require.ErrorIs(t, err, apperr.ErrEmailAlreadyExists)
}

func TestUserService_ListUsers_CapsPageSizeAtMax(t *testing.T) {
	users := newFakeUserRepo()
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.ListUsers(context.Background(), 1000, 0)

	require.NoError(t, err)
	assert.Equal(t, int64(100), users.lastListLimit)
}

func TestUserService_ListUsers_DefaultsWhenLimitNotPositive(t *testing.T) {
	users := newFakeUserRepo()
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	_, err := svc.ListUsers(context.Background(), 0, 0)

	require.NoError(t, err)
	assert.Equal(t, int64(20), users.lastListLimit)
}

func TestUserService_DeactivateUser_SetsInactive(t *testing.T) {
	users := newFakeUserRepo()
	u := activeUser("alice@example.com", "password123")
	users.add(u)
	svc := newTestUserService(users, newFakeResetTokenRepoFull(), &fakeMailer{})

	require.NoError(t, svc.DeactivateUser(context.Background(), u.ID))

	assert.False(t, users.byID[u.ID].Active)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -run TestUserService -v`
Expected: FAIL — `undefined: NewUserService`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/service/user_service.go
package service

import (
	"context"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type userManagementRepository interface {
	Create(ctx context.Context, u *model.User) error
	FindByID(ctx context.Context, id primitive.ObjectID) (*model.User, error)
	List(ctx context.Context, limit, skip int64) ([]*model.User, error)
	Update(ctx context.Context, id primitive.ObjectID, update bson.M) error
}

type UserService struct {
	users       userManagementRepository
	resetTokens resetTokenRepository
	mailer      mailer.Mailer
	resetTTL    time.Duration
	baseURL     string
}

func NewUserService(users userManagementRepository, resetTokens resetTokenRepository, m mailer.Mailer, resetTTL time.Duration, baseURL string) *UserService {
	return &UserService{users: users, resetTokens: resetTokens, mailer: m, resetTTL: resetTTL, baseURL: baseURL}
}

func (s *UserService) CreateUser(ctx context.Context, email, name, role string) (*model.User, error) {
	unusable, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	passwordHash, err := auth.HashPassword(unusable)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	u := &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
		Role:         role,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}

	if err := issuePasswordResetToken(ctx, s.resetTokens, s.mailer, u.ID, u.Email, s.resetTTL, s.baseURL); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) ListUsers(ctx context.Context, limit, skip int64) ([]*model.User, error) {
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	if skip < 0 {
		skip = 0
	}
	return s.users.List(ctx, limit, skip)
}

func (s *UserService) GetUser(ctx context.Context, id primitive.ObjectID) (*model.User, error) {
	return s.users.FindByID(ctx, id)
}

func (s *UserService) UpdateUser(ctx context.Context, id primitive.ObjectID, name, email, role *string) (*model.User, error) {
	update := bson.M{}
	if name != nil {
		update["name"] = *name
	}
	if email != nil {
		update["email"] = *email
	}
	if role != nil {
		update["role"] = *role
	}
	if len(update) > 0 {
		if err := s.users.Update(ctx, id, update); err != nil {
			return nil, err
		}
	}
	return s.users.FindByID(ctx, id)
}

func (s *UserService) DeactivateUser(ctx context.Context, id primitive.ObjectID) error {
	return s.users.Update(ctx, id, bson.M{"active": false})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/service/user_service.go internal/service/user_service_test.go internal/service/auth_service_test.go
git commit -m "feat(service): add UserService for admin-managed user CRUD"
```

---

## Task 15: Initial admin bootstrap

**Files:**
- Create: `internal/bootstrap/seed_admin.go`
- Test: `internal/bootstrap/seed_admin_test.go`

**Interfaces:**
- Consumes: `model.User` (Task 2), `auth.HashPassword` (Task 3), `auth.RoleAdmin` (Task 6).
- Produces:
```go
type adminRepository interface {
    ExistsActiveAdmin(ctx context.Context) (bool, error)
    Create(ctx context.Context, u *model.User) error
}
func SeedAdmin(ctx context.Context, repo adminRepository, email, password string) error
```
Called from `cmd/api/main.go` (Task 21) right after `db.EnsureIndexes`, per the spec's bootstrap flow: no-op if an active admin already exists or if `email`/`password` are empty (no `SEED_ADMIN_*` env vars set).

- [ ] **Step 1: Write the failing test**

```go
// internal/bootstrap/seed_admin_test.go
package bootstrap

import (
	"context"
	"testing"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAdminRepo struct {
	hasAdmin bool
	created  *model.User
}

func (f *fakeAdminRepo) ExistsActiveAdmin(ctx context.Context) (bool, error) {
	return f.hasAdmin, nil
}

func (f *fakeAdminRepo) Create(ctx context.Context, u *model.User) error {
	f.created = u
	return nil
}

func TestSeedAdmin_CreatesAdminWhenNoneExists(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: false}

	err := SeedAdmin(context.Background(), repo, "admin@example.com", "s3cure-password")

	require.NoError(t, err)
	require.NotNil(t, repo.created)
	assert.Equal(t, "admin@example.com", repo.created.Email)
	assert.Equal(t, string(auth.RoleAdmin), repo.created.Role)
	assert.True(t, auth.ComparePassword(repo.created.PasswordHash, "s3cure-password"))
}

func TestSeedAdmin_NoOpWhenAdminAlreadyExists(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: true}

	err := SeedAdmin(context.Background(), repo, "admin@example.com", "s3cure-password")

	require.NoError(t, err)
	assert.Nil(t, repo.created)
}

func TestSeedAdmin_NoOpWhenCredentialsEmpty(t *testing.T) {
	repo := &fakeAdminRepo{hasAdmin: false}

	err := SeedAdmin(context.Background(), repo, "", "")

	require.NoError(t, err)
	assert.Nil(t, repo.created)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/bootstrap/... -v`
Expected: FAIL — `undefined: SeedAdmin`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/bootstrap/seed_admin.go
package bootstrap

import (
	"context"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type adminRepository interface {
	ExistsActiveAdmin(ctx context.Context) (bool, error)
	Create(ctx context.Context, u *model.User) error
}

func SeedAdmin(ctx context.Context, repo adminRepository, email, password string) error {
	if email == "" || password == "" {
		return nil
	}

	exists, err := repo.ExistsActiveAdmin(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	return repo.Create(ctx, &model.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		PasswordHash: hash,
		Name:         "Admin",
		Role:         string(auth.RoleAdmin),
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/bootstrap/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/bootstrap
git commit -m "feat(bootstrap): seed initial admin user from env vars on startup"
```

---

## Task 16: JWTAuth middleware

**Files:**
- Create: `internal/middleware/jwt_auth.go`
- Test: `internal/middleware/jwt_auth_test.go`

**Interfaces:**
- Consumes: `auth.ParseAccessToken`, `auth.GenerateAccessToken` (Task 5), `apperr.ErrTokenInvalid`/`ErrTokenExpired` (Task 2).
- Produces: `middleware.JWTAuth(secret string) echo.MiddlewareFunc`. On success, sets `c.Set("userID", claims.UserID)` and `c.Set("role", claims.Role)` (both strings) before calling `next`. On failure, returns the domain error (`apperr.ErrTokenInvalid` / `ErrTokenExpired`) instead of writing a response directly — `ErrorHandler` (Task 18) is what turns it into a response. Used by `cmd/api/main.go` (Task 21) as route middleware, and by `RequirePermission` (Task 17), which reads the context values this sets.

- [ ] **Step 1: Write the failing test**

```go
// internal/middleware/jwt_auth_test.go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTAuth_ValidTokenSetsContextAndCallsNext(t *testing.T) {
	e := echo.New()
	token, err := auth.GenerateAccessToken("user-1", "admin", "secret", time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var gotUserID, gotRole string
	handler := JWTAuth("secret")(func(c echo.Context) error {
		gotUserID = c.Get("userID").(string)
		gotRole = c.Get("role").(string)
		return c.NoContent(http.StatusOK)
	})

	err = handler(c)

	require.NoError(t, err)
	assert.Equal(t, "user-1", gotUserID)
	assert.Equal(t, "admin", gotRole)
}

func TestJWTAuth_MissingHeaderReturnsTokenInvalid(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth("secret")(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	assert.ErrorIs(t, err, apperr.ErrTokenInvalid)
}

func TestJWTAuth_ExpiredTokenReturnsTokenExpired(t *testing.T) {
	e := echo.New()
	token, err := auth.GenerateAccessToken("user-1", "admin", "secret", -time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth("secret")(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err = handler(c)

	assert.ErrorIs(t, err, apperr.ErrTokenExpired)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/... -run TestJWTAuth -v`
Expected: FAIL — `undefined: JWTAuth`

- [ ] **Step 3: Write minimal implementation**

```go
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
		return func(c echo.Context) error {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get github.com/labstack/echo/v5@latest && go test ./internal/middleware/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/jwt_auth.go internal/middleware/jwt_auth_test.go
git commit -m "feat(middleware): add JWTAuth middleware"
```

---

## Task 17: RequirePermission middleware

**Files:**
- Create: `internal/middleware/require_permission.go`
- Test: `internal/middleware/require_permission_test.go`

**Interfaces:**
- Consumes: `auth.HasPermission`, `auth.Role`, `auth.Permission` (Task 6), `apperr.ErrPermissionDenied` (Task 2), the `"role"` context value set by `JWTAuth` (Task 16).
- Produces: `middleware.RequirePermission(perm auth.Permission) echo.MiddlewareFunc`. Must run after `JWTAuth` in the chain. Used by `cmd/api/main.go` (Task 21) on every admin-only route.

- [ ] **Step 1: Write the failing test**

```go
// internal/middleware/require_permission_test.go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirePermission_AllowsRoleWithPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("role", string(auth.RoleAdmin))

	handler := RequirePermission(auth.PermUserCreate)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_BlocksRoleWithoutPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("role", string(auth.RoleStaff))

	handler := RequirePermission(auth.PermUserCreate)(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	err := handler(c)

	assert.ErrorIs(t, err, apperr.ErrPermissionDenied)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/... -run TestRequirePermission -v`
Expected: FAIL — `undefined: RequirePermission`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/middleware/require_permission.go
package middleware

import (
	"bom-tanstack-api/internal/apperr"
	"bom-tanstack-api/internal/auth"

	"github.com/labstack/echo/v5"
)

func RequirePermission(perm auth.Permission) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			role, _ := c.Get("role").(string)
			if !auth.HasPermission(auth.Role(role), perm) {
				return apperr.ErrPermissionDenied
			}
			return next(c)
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/middleware/... -v`
Expected: PASS (all tests in the package, including Task 16's)

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/require_permission.go internal/middleware/require_permission_test.go
git commit -m "feat(middleware): add RequirePermission middleware"
```

---

## Task 18: Centralized error handler

**Files:**
- Create: `internal/middleware/error_handler.go`
- Test: `internal/middleware/error_handler_test.go`

**Interfaces:**
- Consumes: `apperr.*` (Task 2).
- Produces: `middleware.ErrorHandler(err error, c echo.Context)`, matching Echo's `echo.HTTPErrorHandler` signature. Wired in `cmd/api/main.go` (Task 21) via `e.HTTPErrorHandler = middleware.ErrorHandler`. This is what turns errors returned by `JWTAuth`, `RequirePermission`, and every handler (Tasks 19–20) into the actual HTTP response.

- [ ] **Step 1: Write the failing test**

```go
// internal/middleware/error_handler_test.go
package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bom-tanstack-api/internal/apperr"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func TestErrorHandler_MapsDomainErrorsToStatusCodes(t *testing.T) {
	cases := []struct {
		err            error
		expectedStatus int
	}{
		{apperr.ErrInvalidCredentials, http.StatusUnauthorized},
		{apperr.ErrTokenInvalid, http.StatusUnauthorized},
		{apperr.ErrTokenExpired, http.StatusUnauthorized},
		{apperr.ErrUserInactive, http.StatusForbidden},
		{apperr.ErrPermissionDenied, http.StatusForbidden},
		{apperr.ErrUserNotFound, http.StatusNotFound},
		{apperr.ErrEmailAlreadyExists, http.StatusConflict},
	}

	for _, tc := range cases {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		ErrorHandler(tc.err, c)

		assert.Equal(t, tc.expectedStatus, rec.Code, "error: %v", tc.err)
	}
}

func TestErrorHandler_UnknownErrorReturns500WithGenericMessage(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	ErrorHandler(assert.AnError, c)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	body := decodeErrorBody(t, rec)
	assert.Equal(t, "internal server error", body["error"])
	assert.NotContains(t, rec.Body.String(), assert.AnError.Error())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/... -run TestErrorHandler -v`
Expected: FAIL — `undefined: ErrorHandler`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/middleware/error_handler.go
package middleware

import (
	"errors"
	"net/http"

	"bom-tanstack-api/internal/apperr"

	"github.com/labstack/echo/v5"
)

func ErrorHandler(err error, c echo.Context) {
	status := http.StatusInternalServerError
	message := "internal server error"

	switch {
	case errors.Is(err, apperr.ErrInvalidCredentials),
		errors.Is(err, apperr.ErrTokenInvalid),
		errors.Is(err, apperr.ErrTokenExpired):
		status, message = http.StatusUnauthorized, err.Error()
	case errors.Is(err, apperr.ErrUserInactive),
		errors.Is(err, apperr.ErrPermissionDenied):
		status, message = http.StatusForbidden, err.Error()
	case errors.Is(err, apperr.ErrUserNotFound):
		status, message = http.StatusNotFound, err.Error()
	case errors.Is(err, apperr.ErrEmailAlreadyExists):
		status, message = http.StatusConflict, err.Error()
	default:
		var he *echo.HTTPError
		if errors.As(err, &he) {
			status = he.Code
			if s, ok := he.Message.(string); ok {
				message = s
			}
		} else {
			c.Logger().Error(err)
		}
	}

	if c.Response().Committed {
		return
	}
	_ = c.JSON(status, map[string]string{"error": message})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/middleware/... -v`
Expected: PASS (all tests in the package, including Tasks 16–17's)

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/error_handler.go internal/middleware/error_handler_test.go
git commit -m "feat(middleware): add centralized error handler mapping domain errors to HTTP status"
```

---

## Task 19: Validator wiring

**Files:**
- Create: `internal/httpvalidator/validator.go`
- Test: `internal/httpvalidator/validator_test.go`

**Interfaces:**
- Produces: `httpvalidator.New() *Validator` implementing Echo's `Validate(i interface{}) error` interface (`type Validator struct{ v *validator.Validate }`). Wired into the Echo instance in `cmd/api/main.go` (`e.Validator = httpvalidator.New()`, Task 21) so every handler's `c.Bind()` + `c.Validate()` call (Tasks 20–21) works.

- [ ] **Step 1: Write the failing test**

```go
// internal/httpvalidator/validator_test.go
package httpvalidator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sampleRequest struct {
	Email string `validate:"required,email"`
}

func TestValidator_ValidStructPasses(t *testing.T) {
	v := New()

	err := v.Validate(&sampleRequest{Email: "user@example.com"})

	require.NoError(t, err)
}

func TestValidator_InvalidStructFails(t *testing.T) {
	v := New()

	err := v.Validate(&sampleRequest{Email: "not-an-email"})

	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpvalidator/... -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/httpvalidator/validator.go
package httpvalidator

import "github.com/go-playground/validator/v10"

type Validator struct {
	v *validator.Validate
}

func New() *Validator {
	return &Validator{v: validator.New()}
}

func (cv *Validator) Validate(i interface{}) error {
	return cv.v.Struct(i)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get github.com/go-playground/validator/v10@latest && go test ./internal/httpvalidator/... -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add internal/httpvalidator go.mod go.sum
git commit -m "feat(httpvalidator): wire go-playground/validator into Echo"
```

---

## Task 20: AuthHandler and UserHandler

**Files:**
- Create: `internal/handler/auth_handler.go`
- Create: `internal/handler/user_handler.go`
- Test: `internal/handler/auth_handler_test.go`
- Test: `internal/handler/user_handler_test.go`

**Interfaces:**
- Consumes: `AuthService`/`UserService` public methods (Tasks 13–14, matched structurally by narrower interfaces declared here), `apperr.*` (Task 2), `auth.Role` (Task 6), `httpvalidator.New` (Task 19) — used only in tests to exercise real validation.
- Produces:
```go
type AuthHandler struct{ /* unexported service authServicer */ }
func NewAuthHandler(svc authServicer) *AuthHandler
func (h *AuthHandler) Login(c echo.Context) error
func (h *AuthHandler) Refresh(c echo.Context) error
func (h *AuthHandler) ForgotPassword(c echo.Context) error
func (h *AuthHandler) ResetPassword(c echo.Context) error
func (h *AuthHandler) Me(c echo.Context) error
func (h *AuthHandler) ChangePassword(c echo.Context) error
func (h *AuthHandler) Logout(c echo.Context) error
func (h *AuthHandler) LogoutAll(c echo.Context) error

type UserHandler struct{ /* unexported service userServicer */ }
func NewUserHandler(svc userServicer) *UserHandler
func (h *UserHandler) Create(c echo.Context) error
func (h *UserHandler) List(c echo.Context) error
func (h *UserHandler) Get(c echo.Context) error
func (h *UserHandler) Update(c echo.Context) error
func (h *UserHandler) Delete(c echo.Context) error
```
Registered onto routes in `cmd/api/main.go` (Task 21), which also supplies the real `*service.AuthService`/`*service.UserService` — both satisfy `authServicer`/`userServicer` structurally.

- [ ] **Step 1: Write the failing tests**

```go
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
```

```go
// internal/handler/user_handler_test.go
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
	c.SetParamNames("id")
	c.SetParamValues(primitive.NewObjectID().Hex())

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
	c.SetParamNames("id")
	c.SetParamValues(primitive.NewObjectID().Hex())

	err := h.Delete(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -v`
Expected: FAIL — `undefined: NewAuthHandler`

- [ ] **Step 3: Write minimal implementation**

```go
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

func contextUserID(c echo.Context) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Get("userID").(string))
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (h *AuthHandler) Login(c echo.Context) error {
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

func (h *AuthHandler) Refresh(c echo.Context) error {
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

func (h *AuthHandler) Logout(c echo.Context) error {
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

func (h *AuthHandler) LogoutAll(c echo.Context) error {
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

func (h *AuthHandler) ForgotPassword(c echo.Context) error {
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

func (h *AuthHandler) ResetPassword(c echo.Context) error {
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

func (h *AuthHandler) ChangePassword(c echo.Context) error {
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

func (h *AuthHandler) Me(c echo.Context) error {
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
```

```go
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

func paramObjectID(c echo.Context) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(c.Param("id"))
}

type createUserRequest struct {
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name" validate:"required"`
	Role  string `json:"role" validate:"required,oneof=admin manager staff viewer"`
}

func (h *UserHandler) Create(c echo.Context) error {
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

func (h *UserHandler) List(c echo.Context) error {
	limit, _ := strconv.ParseInt(c.QueryParam("limit"), 10, 64)
	skip, _ := strconv.ParseInt(c.QueryParam("skip"), 10, 64)

	users, err := h.service.ListUsers(c.Request().Context(), limit, skip)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, users)
}

func (h *UserHandler) Get(c echo.Context) error {
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

func (h *UserHandler) Update(c echo.Context) error {
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

func (h *UserHandler) Delete(c echo.Context) error {
	id, err := paramObjectID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}
	if err := h.service.DeactivateUser(c.Request().Context(), id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go get github.com/go-playground/validator/v10@latest && go test ./internal/handler/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/handler
git commit -m "feat(handler): add AuthHandler and UserHandler"
```

---

## Task 21: Router wiring

**Files:**
- Create: `internal/router/router.go`
- Test: `internal/router/router_test.go`

**Interfaces:**
- Consumes: `httpvalidator.New` (Task 19), `middleware.JWTAuth`/`RequirePermission`/`ErrorHandler` (Tasks 16–18), `handler.AuthHandler`/`UserHandler` and their public methods (Task 20), `auth.Perm*` (Task 6).
- Produces: `router.New(jwtSecret string, authHandler *handler.AuthHandler, userHandler *handler.UserHandler) *echo.Echo`. Called from `cmd/api/main.go` (Task 22) once real dependencies are wired. Kept separate from `main.go` specifically so route registration and middleware gating are testable with `httptest` — `main.go` itself has no branching logic left to unit test once this exists.

Registers:
- `GET /healthz` — no auth, returns `200 {"status":"ok"}`
- `POST /api/v1/auth/login`, `/refresh`, `/forgot-password`, `/reset-password` — no auth
- `GET /api/v1/auth/me`, `POST /api/v1/auth/change-password`, `/logout`, `/logout-all` — `JWTAuth` only
- `POST /api/v1/users` — `JWTAuth` + `RequirePermission(PermUserCreate)`
- `GET /api/v1/users` — `JWTAuth` + `RequirePermission(PermUserRead)`
- `GET /api/v1/users/:id` — `JWTAuth` + `RequirePermission(PermUserRead)`
- `PATCH /api/v1/users/:id` — `JWTAuth` + `RequirePermission(PermUserUpdate)`
- `DELETE /api/v1/users/:id` — `JWTAuth` + `RequirePermission(PermUserDelete)`

- [ ] **Step 1: Write the failing test**

```go
// internal/router/router_test.go
package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bom-tanstack-api/internal/auth"
	"bom-tanstack-api/internal/handler"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouter_Healthz_NoAuthRequired(t *testing.T) {
	e := New("secret", handler.NewAuthHandler(&stubAuthServicer{}), handler.NewUserHandler(&stubUserServicer{}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRouter_CreateUser_WithoutTokenReturns401(t *testing.T) {
	e := New("secret", handler.NewAuthHandler(&stubAuthServicer{}), handler.NewUserHandler(&stubUserServicer{}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRouter_CreateUser_WithStaffTokenReturns403(t *testing.T) {
	e := New("secret", handler.NewAuthHandler(&stubAuthServicer{}), handler.NewUserHandler(&stubUserServicer{}))
	token, err := auth.GenerateAccessToken("user-1", "staff", "secret", time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRouter_Me_WithValidTokenReturns200(t *testing.T) {
	e := New("secret", handler.NewAuthHandler(&stubAuthServicer{}), handler.NewUserHandler(&stubUserServicer{}))
	token, err := auth.GenerateAccessToken("user-1", "admin", "secret", time.Minute)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
```

Add these minimal stubs (satisfying the same `authServicer`/`userServicer` interfaces exercised in Task 20, redeclared here for the router test — the router package can't import `handler`'s unexported interfaces, so it needs its own real usages via the exported `handler.AuthHandler`/`UserHandler` structs, which is what the test above already does; the stubs below just need to implement the interfaces those constructors accept):

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/router/... -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write minimal implementation**

```go
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

	e.GET("/healthz", func(c echo.Context) error {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/router/... -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/router
git commit -m "feat(router): wire routes, JWTAuth, and RequirePermission middleware"
```

---

## Task 22: main.go — wire real dependencies and start the server

**Files:**
- Create: `cmd/api/main.go`

**Interfaces:**
- Consumes every package's constructor from Tasks 1–21: `config.Load`, `db.Connect`/`EnsureIndexes`, `repository.New*Repository`, `mailer.NewSMTPMailer`, `bootstrap.SeedAdmin`, `service.NewAuthService`/`NewUserService`, `handler.NewAuthHandler`/`NewUserHandler`, `router.New`.
- Produces: the running binary; nothing else depends on this file.

This task has no unit test — it is pure dependency wiring with no branching logic of its own (every decision it could make was already pushed into `router.New`, tested in Task 21). Correctness is verified by `go build` and the manual smoke steps below, which require a real MongoDB reachable at `MONGO_URI`.

- [ ] **Step 1: Write the implementation**

```go
// cmd/api/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bom-tanstack-api/internal/bootstrap"
	"bom-tanstack-api/internal/config"
	"bom-tanstack-api/internal/db"
	"bom-tanstack-api/internal/handler"
	"bom-tanstack-api/internal/mailer"
	"bom-tanstack-api/internal/repository"
	"bom-tanstack-api/internal/router"
	"bom-tanstack-api/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := db.Connect(ctx, cfg.MongoURI)
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}
	database := client.Database(cfg.MongoDBName)

	if err := db.EnsureIndexes(ctx, database); err != nil {
		log.Fatalf("ensure indexes: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	refreshTokenRepo := repository.NewRefreshTokenRepository(database)
	resetTokenRepo := repository.NewPasswordResetTokenRepository(database)

	if err := bootstrap.SeedAdmin(ctx, userRepo, cfg.SeedAdminEmail, cfg.SeedAdminPassword); err != nil {
		log.Fatalf("seed admin: %v", err)
	}
	adminExists, err := userRepo.ExistsActiveAdmin(ctx)
	if err != nil {
		log.Fatalf("check existing admin: %v", err)
	}
	if !adminExists {
		log.Println("warning: no active admin exists and SEED_ADMIN_EMAIL/SEED_ADMIN_PASSWORD were not both set — /api/v1/users is unreachable until an admin is created")
	}

	mailerClient := mailer.NewSMTPMailer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom)

	authService := service.NewAuthService(
		userRepo, refreshTokenRepo, resetTokenRepo, mailerClient,
		cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.ResetTokenTTL, cfg.AppBaseURL,
	)
	userService := service.NewUserService(userRepo, resetTokenRepo, mailerClient, cfg.ResetTokenTTL, cfg.AppBaseURL)

	authHandler := handler.NewAuthHandler(authService)
	userHandler := handler.NewUserHandler(userService)

	e := router.New(cfg.JWTSecret, authHandler, userHandler)

	go func() {
		if err := e.Start(":" + cfg.Port); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := e.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown: %v", err)
	}
	if err := client.Disconnect(shutdownCtx); err != nil {
		log.Printf("mongo disconnect: %v", err)
	}
}
```

- [ ] **Step 2: Verify the build**

Run: `go build ./...`
Expected: exits 0, no errors.

- [ ] **Step 3: Manual smoke test**

Run a local MongoDB (`docker run -d -p 27017:27017 mongo:7`), then:

```bash
export MONGO_URI="mongodb://localhost:27017"
export MONGO_DB_NAME="bomtanstack"
export JWT_SECRET="dev-secret-change-me"
export SMTP_HOST="localhost"
export SMTP_PORT="1025"
export SMTP_FROM="no-reply@example.com"
export APP_BASE_URL="http://localhost:8080"
export SEED_ADMIN_EMAIL="admin@example.com"
export SEED_ADMIN_PASSWORD="change-me-now"

go run ./cmd/api
```

In another terminal:
```bash
curl -s http://localhost:8080/healthz
# Expected: {"status":"ok"}

curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"change-me-now"}'
# Expected: {"accessToken":"...","refreshToken":"..."}
```

- [ ] **Step 4: Commit**

```bash
git add cmd/api/main.go
git commit -m "feat(cmd/api): wire dependencies and start the HTTP server"
```

---

## Post-Plan Verification

After Task 22, run the full suite before considering this module done:

```bash
go build ./...
go vet ./...
go test ./...
go test -tags=integration ./...
```

All four must pass with no failures before this module is considered complete.
