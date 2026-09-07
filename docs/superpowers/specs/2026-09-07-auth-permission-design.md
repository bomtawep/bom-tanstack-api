# Auth + Permission (RBAC) — Design Spec

Date: 2026-09-07
Status: Approved for planning

## Context

`bom-tanstack-api` is a backend for an online sales management system (products, orders,
inventory, customers). Those modules will each get their own spec later, but all of them
depend on knowing who the caller is and what they're allowed to do. This spec covers only
the foundational **Auth + Permission (RBAC)** sub-project — no product/order/inventory
endpoints are in scope here.

## Goals

- Users authenticate via email + password and receive a short-lived access token plus a
  refresh token.
- A fixed set of roles (Admin, Manager, Staff, Viewer) gates access to endpoints via
  resource:action permissions.
- Admins can provision and manage user accounts; there is no public self-registration.
- Users can recover a forgotten password via a self-service email flow.
- Multiple concurrent sessions (devices) per user are supported and individually revocable.

## Non-Goals

- Product, order, inventory, or customer management endpoints (separate specs).
- Dynamic/editable permissions (role → permission mapping is hardcoded in code, per
  explicit decision below).
- Public self-registration.
- Multi-tenancy (single organization/shop per deployment).

## Decisions Made During Brainstorming

| Question | Decision |
|---|---|
| Permission granularity | Fixed roles (Admin, Manager, Staff, Viewer) |
| Roles needed | Admin, Manager, Staff, Viewer |
| Auth mechanism | JWT — short-lived access token + long-lived refresh token |
| User provisioning | Admin creates users; no public signup |
| Forgot password | Self-service via email |
| Email delivery | Plain SMTP (config via env), no third-party API |
| Role → permission mapping | Hardcoded in code, not editable via API/DB |
| Multi-session | Supported — refresh tokens tracked per device, individually revocable |

## Architecture

```
cmd/api/main.go              — bootstrap: config, mongo client, echo server, route registration
internal/config/             — env-based config (Mongo URI, JWT secret, token TTLs, SMTP settings)
internal/model/              — User, RefreshToken, PasswordResetToken
internal/repository/         — UserRepository, RefreshTokenRepository, PasswordResetTokenRepository
internal/service/            — AuthService (login/refresh/logout/reset-password), UserService (admin user management)
internal/handler/            — AuthHandler, UserHandler
internal/middleware/         — JWTAuth (verifies access token, sets user in context), RequirePermission
internal/auth/               — permissions.go (role→permission map), jwt.go (sign/parse), password.go (bcrypt)
internal/mailer/             — SMTP email sending for password reset
```

- `internal/auth/permissions.go` is the single source of truth for `map[Role][]Permission`.
  Future modules (product, order, ...) add new permission constants here rather than
  inventing a parallel mechanism.
- Middleware chain per protected route: `JWTAuth` (authenticate) → `RequirePermission("x:y")`
  (authorize).
- `AuthService` / `UserService` depend only on repository interfaces — no direct Echo or
  Mongo driver imports, per the layering rules in `CLAUDE.md`.

## Data Model

### `users` collection
```go
type User struct {
    ID           primitive.ObjectID `bson:"_id" json:"id"`
    Email        string             `bson:"email" json:"email"`
    PasswordHash string             `bson:"password_hash" json:"-"`
    Name         string             `bson:"name" json:"name"`
    Role         string             `bson:"role" json:"role"` // admin | manager | staff | viewer
    Active       bool               `bson:"active" json:"active"`
    CreatedAt    time.Time          `bson:"created_at" json:"createdAt"`
    UpdatedAt    time.Time          `bson:"updated_at" json:"updatedAt"`
}
```
- Unique index on `email`.
- `Active=false` is how an account is disabled; users are never hard-deleted.

### `refresh_tokens` collection
```go
type RefreshToken struct {
    ID        primitive.ObjectID `bson:"_id" json:"id"`
    UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
    TokenHash string             `bson:"token_hash" json:"-"` // sha256 of the raw token; raw token is never persisted
    UserAgent string             `bson:"user_agent" json:"userAgent"`
    ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"`
    RevokedAt *time.Time         `bson:"revoked_at,omitempty" json:"revokedAt,omitempty"`
    CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
```
- Index on `user_id` (list/revoke sessions for a user).
- TTL index on `expires_at` for automatic cleanup.

### `password_reset_tokens` collection
```go
type PasswordResetToken struct {
    ID        primitive.ObjectID `bson:"_id" json:"id"`
    UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
    TokenHash string             `bson:"token_hash" json:"-"`
    ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"` // short-lived, 30 minutes
    UsedAt    *time.Time         `bson:"used_at,omitempty" json:"usedAt,omitempty"`
    CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}
```
- TTL index on `expires_at`.
- Only the token hash is stored; the raw token is emailed to the user and never persisted.

## API Endpoints

### Public
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | email + password → access token + refresh token |
| POST | `/api/v1/auth/refresh` | refresh token → new access token + new refresh token (rotated) |
| POST | `/api/v1/auth/forgot-password` | sends reset email if the account exists; always responds 200 |
| POST | `/api/v1/auth/reset-password` | sets a new password using a valid reset token |

### Authenticated (requires `JWTAuth`)
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/auth/me` | current user profile, role, and effective permissions |
| POST | `/api/v1/auth/change-password` | self-service password change (requires current password) |
| POST | `/api/v1/auth/logout` | revokes the refresh token for the current device |
| POST | `/api/v1/auth/logout-all` | revokes all refresh tokens for the current user |

### Admin-only (requires `JWTAuth` + `RequirePermission`)
| Method | Path | Permission |
|---|---|---|
| POST | `/api/v1/users` | `user:create` |
| GET | `/api/v1/users` | `user:read` |
| GET | `/api/v1/users/:id` | `user:read` |
| PATCH | `/api/v1/users/:id` | `user:update` |
| DELETE | `/api/v1/users/:id` | `user:delete` (soft-delete: sets `active=false`) |

### Initial role → permission mapping
- Admin: `user:create`, `user:read`, `user:update`, `user:delete`
- Manager: `user:read`
- Staff, Viewer: none of the `user:*` permissions

## Key Flows

**Admin creates a user**: `UserService` creates the document with `PasswordHash` set to a
hash of random bytes (never revealed to anyone — it is not a usable password), then
immediately generates a password-reset token and emails it, reusing the forgot-password
flow below. The new user's first action is always to set their own password via
`/api/v1/auth/reset-password`; there is no separate "welcome email" mechanism.

**Login**: look up user by email → verify `active=true` → bcrypt-compare password → issue
access token (JWT, 15 min TTL, claims include user ID + role) and a refresh token (random
32 bytes; only its SHA-256 hash is stored, 30-day TTL).

**Refresh (rotation)**: hash the incoming token → look up an unrevoked, unexpired match →
revoke it immediately and issue a new access/refresh pair. Rotation prevents replay of a
stolen refresh token past its first use.

**Forgot / reset password**: generate a reset token in a separate collection, 30-minute
TTL, email the raw token as a link (never persisted in raw form). On successful reset,
revoke *all* refresh tokens for that user, forcing re-login on every device.

**Permission check**: `JWTAuth` verifies the access token and loads the role into request
context; `RequirePermission("resource:action")` checks that role's entry in
`internal/auth/permissions.go`.

## Error Handling

Domain errors returned by the service layer: `ErrInvalidCredentials`, `ErrUserNotFound`,
`ErrUserInactive`, `ErrEmailAlreadyExists`, `ErrTokenInvalid`, `ErrTokenExpired`,
`ErrPermissionDenied`. These are mapped centrally in
`internal/middleware/error_handler.go`:

| Domain error | HTTP status |
|---|---|
| `ErrInvalidCredentials`, `ErrTokenInvalid`, `ErrTokenExpired` | 401 |
| `ErrUserInactive`, `ErrPermissionDenied` | 403 |
| `ErrUserNotFound` | 404 |
| `ErrEmailAlreadyExists` | 409 |
| validation error (`c.Validate()`) | 400 |

Login and forgot-password never reveal whether an email exists — both a wrong password
and an unknown email return the same `ErrInvalidCredentials` / generic 200, respectively.
No handler surfaces raw Mongo driver errors or stack traces to the client.

## Testing Plan

- **Service unit tests**: mock `UserRepository` / `RefreshTokenRepository`. Cover
  successful login, wrong password, inactive user, refresh-token rotation, reset-password
  revoking all sessions, and the role→permission map contents.
- **Handler unit tests**: `httptest` + Echo context with a mocked service. Cover response
  status/shape per error case, and that `RequirePermission` blocks (403) or allows (200)
  based on role.
- **Repository integration tests** (build tag `integration`, real MongoDB via
  testcontainers): unique index on `email` rejects duplicates; `FindOne` misses map to
  `ErrUserNotFound`; indexes exist as declared.
- **Security-focused cases**: password hashes are never plaintext; a JWT with a bad
  signature or expired `exp` is rejected; a refresh token reused after rotation is
  rejected (replay protection).

## Open Items For Later Specs

- Product / Inventory / Order / Customer management modules will consume
  `internal/auth/permissions.go` and add their own permission constants — not designed
  here.
