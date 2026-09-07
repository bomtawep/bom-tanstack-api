# Security Rules — bom-tanstack-api (Go + Echo + MongoDB)

## Input Handling
- Every handler binds and validates input via `c.Bind()` + `c.Validate()` (struct tags via `go-playground/validator`) before it touches any service/repository code — never trust query params, path params, or body fields as-is
- Validate and parse `primitive.ObjectID` from path/query params explicitly (`primitive.ObjectIDFromHex`) before use — an invalid hex string must return 400, not panic or reach the driver
- Reject or strip user-supplied keys that start with `$` or contain `.` before they can reach a `bson.M`/`bson.D` filter — this is the NoSQL-injection equivalent of SQL parameterization. Never build a Mongo filter by interpolating raw user input into an operator position (e.g. never let a client control which operator runs, only the value being compared)
- Never pass user-controlled data into `$where`, `$function`, or `mapReduce` — these execute JavaScript server-side

## AuthN / AuthZ
- Authentication is enforced via Echo middleware, not inside individual handlers
- Authorization (ownership/role checks) happens in the service layer against the authenticated identity from context — never trust an ID passed in the request body/query for "which record to act on" without checking it belongs to the caller
- JWT (or session) secrets/signing keys come from `internal/config` (env-backed), never hardcoded, never logged
- Passwords (if applicable) are hashed with `bcrypt` or `argon2id` — never stored or logged in plaintext, never compared with `==`

## Secrets & Config
- All secrets (Mongo URI, JWT signing key, API keys) load through `internal/config` from environment variables — never hardcoded, never committed
- `.env` stays in `.gitignore`; only commit `.env.example` with placeholder values
- MongoDB connection uses a least-privilege application user (read/write only on its own database), not an admin credential

## Error Handling & Responses
- The centralized error handler (`internal/middleware/error_handler.go`) maps internal/domain errors to HTTP status codes and a generic client-facing message — raw error strings, stack traces, and driver-level details (e.g. Mongo error text) must never reach the response body
- Full error detail is logged server-side (with request context) at the point of failure, not exposed to the client

## Transport & Headers
- Enforce HTTPS/TLS termination in front of the service (load balancer/reverse proxy); do not serve plaintext HTTP in production
- Use Echo's `secure` middleware (or equivalent) to set standard security headers (`X-Content-Type-Options`, `X-Frame-Options`, HSTS, etc.)
- CORS is configured with an explicit origin allowlist — never `AllowOrigins: ["*"]` alongside credentials

## Rate Limiting & Abuse
- Public/unauthenticated endpoints (login, signup, password reset) are rate-limited via middleware
- List endpoints always enforce a max page size server-side (`options.Find().SetLimit(...)`), regardless of what the client requests, to prevent resource-exhaustion via unbounded queries

## Logging
- Never log secrets, tokens, passwords, or full request/response bodies that may contain PII
- Log identifiers (user ID, request ID) instead of sensitive payloads for traceability

## Dependencies
- Run `govulncheck ./...` as part of the review process before merging dependency updates
- Keep `go.mod`/`go.sum` tidy (`go mod tidy`) and avoid adding dependencies with broad, unreviewed transitive trees for security-sensitive functionality (auth, crypto)