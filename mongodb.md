# MongoDB Rules — bom-tanstack-api (Go + Echo + MongoDB)

## Driver & Connection
- Use the official driver `go.mongodb.org/mongo-driver/mongo` (check `go.mod` for v1 vs v2 — API differs, e.g. v2 drops `bson.M` in favor of explicit builders in some helpers)
- Create a single `*mongo.Client` at startup (`cmd/api/main.go`), reused for the process lifetime — never call `mongo.Connect` per-request
- Verify connectivity at startup with `client.Ping(ctx, readpref.Primary())` and fail fast if it doesn't succeed
- Read the connection URI, database name, and any credentials from `internal/config` (env-backed) — never hardcode a URI or embed credentials in code
- Set explicit timeouts on the client (`connectTimeoutMS`, `serverSelectionTimeoutMS`) rather than relying on driver defaults, so a down database fails fast instead of hanging requests
- Close the client on graceful shutdown (`client.Disconnect(ctx)`), tied to the same shutdown path as the Echo server

## Repository Layer
- One repository struct per collection (e.g. `UserRepository` wraps a single `*mongo.Collection`); inject `*mongo.Database` via constructor, not a package-level singleton
- All Mongo access goes through the repository layer — handlers and services never import `go.mongodb.org/mongo-driver` directly
- Every repository method accepts `context.Context` as its first argument and passes it straight through to the driver call (`FindOne(ctx, ...)`, `InsertOne(ctx, ...)`, etc.) — never `context.Background()` inside a repository method
- Repository methods return domain types and domain errors, never `*mongo.SingleResult`, `bson.M`, or raw driver errors

## Models & BSON Mapping
- Every persisted struct declares both `bson:"field_name"` and `json:"fieldName"` tags explicitly — do not rely on the driver's default lowercase field-name mapping
- Use `primitive.ObjectID` for `_id` fields; use a custom string key only when the domain genuinely requires a non-ObjectID identifier (and document why)
- Use pointers (`*string`, `*int`, ...) or `omitempty` deliberately to distinguish "field absent" from "field zero value" wherever that distinction matters to the domain
- Keep `time.Time` fields in UTC; let the driver handle BSON datetime conversion rather than storing epoch integers

## Queries & Filters
- Build filters with typed `bson.M`/`bson.D` — never construct a filter by string-concatenating user input
- Reject/strip any user-supplied key that starts with `$` or contains `.` before it can reach a filter (NoSQL-injection prevention) — the client controls values, never operators
- Always project only the fields a handler actually needs (`options.Find().SetProjection(...)`) for read-heavy or wide documents
- Never call `Find()` without a limit on a list endpoint — set `options.Find().SetLimit(...)` and support pagination (cursor-based on `_id`, or `skip`/`limit` for small collections only)
- Use `FindOne` + check `errors.Is(err, mongo.ErrNoDocuments)` for single-document lookups; map that to a domain `ErrNotFound` at the repository boundary — never let `mongo.ErrNoDocuments` leak into the service/handler layers

## Writes & Transactions
- Prefer single-document atomic operations (`UpdateOne` with `$set`, `FindOneAndUpdate`) over read-modify-write from application code
- Use `session.WithTransaction` only when a single logical operation must write to multiple collections atomically — this requires a replica set (not a standalone `mongod`); don't reach for transactions to work around a data model that should be denormalized instead
- Use `FindOneAndUpdate`/`FindOneAndDelete` with `options.Return(options.After)` when the caller needs the resulting document, instead of a separate write + read round trip
- Set `bypassDocumentValidation` only with an explicit, documented reason — schema validation should stay on by default if the collection defines one

## Indexes
- Define all indexes explicitly and in code (e.g. `internal/repository/indexes.go`, run once at startup or via a migration step) — never rely on indexes created ad hoc in a shell or created implicitly
- Every field used in a `filter`, `sort`, or as the lookup key in an aggregation `$match`/`$lookup` must have a supporting index — verify with `.explain()` for any non-trivial query
- Use a unique index (not just application-level checks) to enforce uniqueness constraints (e.g. email, username) — application-level "check then insert" has a race condition
- Use TTL indexes for documents that should expire automatically (sessions, tokens) instead of a cron cleanup job

## Aggregation
- Use the aggregation pipeline (`bson.A{...}` stages) for multi-collection joins (`$lookup`) or computed reads — avoid N+1 query patterns where application code loops and issues a query per item
- Keep pipelines readable: build stages as named `bson.D` variables rather than one large inline literal when there are more than 2–3 stages
- Add a `$match` as early as possible in the pipeline to reduce the working set before `$lookup`/`$group`/`$sort`

## Migrations & Schema Evolution
- Any schema change (new required field, renamed field, changed type) ships with a migration/backfill script under `migrations/`, run explicitly — never assume existing documents already match a new struct shape
- Application code that reads older documents must tolerate the pre-migration shape until the backfill has fully run (e.g. treat a missing new field as its zero-value default, not as an error)

## Testing
- Unit-test repository callers (service layer) against a mocked repository interface, not a real database
- Repository-layer tests themselves run as integration tests against a real (containerized) `mongod` — see `testing.md`
