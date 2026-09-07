# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Project: bom-tanstack-api — Go + Echo API

## Project status

This repository is a fresh Go module scaffold with no application code yet. It currently contains only:
- `go.mod` / `go.sum` — module `bom-tanstack-api`, Go 1.27.1, with `github.com/labstack/echo/v5` as a dependency (Echo is a Go web framework, so the API is expected to be built on it)
- `README.md` — title only
- `.gitignore` — standard Go ignores

There is no `main.go`, no handlers, no tests, and no build/lint/test tooling configured yet. When source files are added, this file should be updated with real commands (`go build`, `go test`, `go vet`, etc.) and the actual package/route architecture.

## Build & Test

Standard Go module commands apply:
- Run dev server: `air` (hot reload) or `go run cmd/api/main.go`
- Build: `go build -o bin/api cmd/api/main.go`
- `go test ./...` — run all tests use testify
- `go vet ./...` — static analysis
- `go mod tidy` — sync go.mod/go.sum after adding imports
- Lint: `golangci-lint run`
- Format: `gofmt -w .` and `goimports -w .`

No custom Makefile, linter config, or CI pipeline exists yet in this repo.

## Project Structure
- `cmd/api/` — entrypoint, main.go, server setup
- `internal/handler/` — Echo handlers (HTTP layer only, no business logic)
- `internal/service/` — business logic
- `internal/repository/` — DB access layer
- `internal/model/` — structs / domain types
- `internal/middleware/` — custom Echo middleware
- `pkg/` — shared utilities reusable outside this project
- `migrations/` — DB schema migrations

## Echo Conventions
- Register routes grouped by resource, e.g. `e.Group("/api/v1/users")`
- Handlers return errors via `echo.NewHTTPError(code, message)` — never `panic`
- Use `c.Bind()` + `c.Validate()` for request parsing; validation via `go-playground/validator` struct tags
- Handlers must not contain business logic — call into `service` layer only
- Use context propagation: pass `c.Request().Context()` down to service/repository calls, not `c` itself
- Centralize error → HTTP status mapping in `internal/middleware/error_handler.go`, including mapping `mongo.ErrNoDocuments` → 404

## Code Style
- Follow standard Go naming: exported identifiers PascalCase, unexported camelCase
- Error handling: always check and wrap errors with `fmt.Errorf("context: %w", err)` — never ignore `err`
- Interfaces defined in the consumer package, not the implementer (accept interfaces, return structs)
- No global mutable state; inject `*mongo.Database` via constructor, not a package-level singleton

## MongoDB Conventions
- Use official driver `go.mongodb.org/mongo-driver/mongo` (v2 if applicable — check `go.mod`)
- One repository struct per collection, e.g. `UserRepository` wraps `*mongo.Collection`
- All queries go through `repository` layer — never call `mongo.Collection` directly from handler/service
- Every DB call must accept and pass through `context.Context` (`FindOne(ctx, ...)`, `InsertOne(ctx, ...)`)
- Model structs: define both `bson:"field_name"` and `json:"fieldName"` tags explicitly — don't rely on default field name mapping
- Use `primitive.ObjectID` for `_id`, never plain string, unless the field is intentionally a custom key
- Wrap `mongo.ErrNoDocuments` at repository layer into a domain-level `ErrNotFound` — don't leak driver-specific errors into service/handler layers
- Define indexes explicitly in a migration/seed script (e.g. `internal/repository/indexes.go`), not created ad-hoc at runtime
- Use aggregation pipelines (`bson.A{...}` stages) for multi-collection joins/lookups — avoid N+1 query patterns in application code
- Avoid unbounded `Find()` — always set `options.Find().SetLimit(...)` for list endpoints; support pagination via cursor-based `_id` or `skip/limit`
- Use sessions/transactions (`session.WithTransaction`) only when a write touches multiple collections that must stay consistent — MongoDB replica set required

## Architecture
- Backend: golang + echo
- Database: MongoDB

## Database
- All queries go through `repository` layer — never raw SQL in handlers/services
- New schema changes require a migration file in `migrations/`

## Conventions
- Never commit directly to `develop` `main`
- Run `golangci-lint run` and `go test ./...`
- Environment config loaded via `internal/config` (viper/env) — no hardcoded secrets or URLs