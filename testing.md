# Testing Rules — bom-tanstack-api (Go + Echo + MongoDB)

## Scope & Tools
- Test framework: standard `testing` package + `testify` (`assert` / `require`)
- Mocking: generate mocks for repository/service interfaces (e.g. `mockery` or `gomock`); never mock concrete structs
- HTTP layer tests: `net/http/httptest` + `echo.New()` — never spin up a real network listener for handler tests
- Integration tests against MongoDB: use `testcontainers-go` (real `mongod` in a container) or the driver's `mtest` package for mocked server responses — never point tests at a shared/prod database

## Test Types & Layout
- Unit tests are colocated with source: `foo.go` → `foo_test.go`, same package (or `_test` package suffix for black-box tests of exported API only)
- Integration tests that require a live MongoDB go under a build tag: `//go:build integration` at the top of the file, so `go test ./...` (default) skips them
- Table-driven tests are the default shape for anything with more than 2 input/output cases
- One behavior per test function; name tests `TestXxx_ScenarioDescription`

## Layer-Specific Rules
- **Handler tests**: build the Echo context manually (`e.NewContext(req, rec)`), inject a mocked service, assert on `rec.Code` / `rec.Body`. Do not exercise the real service or repository.
- **Service tests**: inject a mocked repository interface; assert business logic and error propagation, not persistence behavior.
- **Repository tests**: these are the integration tests — run against a real (containerized) MongoDB. Assert on actual query/filter behavior, index usage, and error mapping (e.g. `mongo.ErrNoDocuments` → domain `ErrNotFound`).
- Never assert against `mongo` driver error types outside the repository layer — service/handler tests should only ever see domain errors (`ErrNotFound`, etc.).

## Error & Edge Cases
- Every handler/service test must cover: happy path, validation failure, not-found, and at least one downstream error (repository/service returns an error)
- Use `errors.Is` / `errors.As` when asserting on wrapped errors — never compare error strings
- Test context cancellation/timeout propagation for anything that calls out to MongoDB with a caller-supplied `context.Context`

## Running Tests
- All unit tests: `go test ./...`
- Single package: `go test ./internal/service/...`
- Single test: `go test ./internal/service/... -run TestUserService_Create -v`
- With coverage: `go test -cover ./...`
- Integration suite: `go test -tags=integration ./...`
- Race detector (run before merging anything touching concurrency/shared state): `go test -race ./...`

## What Not to Do
- Don't hit a real, shared MongoDB instance from unit tests
- Don't skip error-path tests because "it's just a pass-through" — repository/service error wrapping is exactly where bugs hide
- Don't assert on exact log output or timestamps
- Don't write tests that depend on execution order between test functions
