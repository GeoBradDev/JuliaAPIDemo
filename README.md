# JuliaAPI Demo

Bearer-token protected API built with Oxygen.jl + PostgreSQL for token storage and logging. This is a learning tool: it shows how to issue and validate API tokens (JWT) backed by a database. There is **no user login system**; humans interact by calling the API with tokens or by using the admin token tools.

## What you get
- Oxygen.jl HTTP API with Swagger docs
- JWT generation/validation (HS256) for API clients
- PostgreSQL-backed token storage and request logging
- Demo-friendly admin endpoints to issue/list/revoke tokens (open by default for learning)

## Docs reference (Oxygen.jl)
- Official docs: https://oxygenframework.github.io/Oxygen.jl/stable/
- Key concepts used here:
  - Routing macros: `@get`, `@post`, `@delete` for concise handlers
  - Middleware: applied via `serve(middleware=[...])` to protect `/api/*`
  - Request/response helpers: simple `Dict` return values become JSON responses
  - Swagger: Oxygen auto-exposes `/docs` and `/openapi` when enabled

## Prerequisites (Docker-focused, beginner friendly)
- **Docker + Docker Compose**: install from https://docs.docker.com/get-docker/. Compose is included in recent Docker Desktop/Engine installs.
- **Git** (optional) to clone the repo.

## Quick start (Docker only)
1) Clone the repo: `git clone <this-repo-url>` and `cd JuliaAPI_Auth`.
2) Create a `.env` file (see sample below).
3) Start everything (API + Postgres):
   ```bash
   docker compose up --build
   ```
   - First run may take a minute to pull images and build.
   - Logs show DB start, then API on port `API_PORT` (default 8080).
4) Open Swagger at http://localhost:8080/docs to explore endpoints.
5) When done: `docker compose down` (add `-v` to also remove the DB volume if you want a clean reset).

## Environment configuration (.env)
Create a `.env` file in the project root (used by Docker Compose). Example safe-for-local-development values:
```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=jwt_api_db
DB_USER=api_user
DB_PASSWORD=password
JWT_SECRET=change-me-in-production
API_PORT=8080
# Demo flag: leaves admin endpoints open (no auth) for learning
DEMO_UNSAFE_ADMIN=true
```
**Important:** In production, set `DEMO_UNSAFE_ADMIN=false` (or remove it) and add real authentication around admin routes.

## Authentication model (human vs API client)
- **API (client) authentication**
  - Clients receive a JWT with `type=api_access`, signed using `JWT_SECRET`.
  - Every `/api/*` request must include `Authorization: Bearer <token>`.
  - The server verifies signature, checks `exp`, and looks up the token hash in the `api_tokens` table to ensure it’s active/not expired; usage is logged to `token_usage_log`.
- **User (human) authentication**
  - There is **no user login/session system**. Humans interact by obtaining a token (via admin routes) and then calling the API as a client.
  - Admin/token-management endpoints are open in demo mode **only for learning and testing**.
- **Critical warning**
  - Admin endpoints (`/admin/issue-token`, `/admin/tokens`, `/admin/tokens/:client_id`, `/admin/usage/:client_id`) are **unauthenticated when `DEMO_UNSAFE_ADMIN=true`**. This is intentionally unsafe for demonstration. In any real deployment, enforce authentication/authorization before exposing them (e.g., behind an authenticated proxy or with a dedicated admin JWT flow).

## First run walkthrough (Docker)
1) `docker compose up --build`
2) Wait for logs: Postgres starts, then API prints `Starting server on port 8080...`
3) Visit `http://localhost:8080/health` — should return `status: ok` and `database: connected`.
4) Visit `http://localhost:8080/docs` — interactive Swagger UI.
5) Issue a token using Swagger or curl (see below), then call a protected endpoint.

## Issue a token (demo mode)
Using curl (admin route is open in demo mode):
```bash
curl -X POST http://localhost:8080/admin/issue-token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"demo-client","client_name":"Demo User","expires_in_days":365,"created_by":"demo"}'
```
Response includes `token` (JWT) and `expires_at`. Store it securely.

## Call a protected endpoint
```bash
TOKEN="<paste token from issue step>"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/data
```
You should see sample data plus `requested_by` from the token context.

## Revoke a token (PATCH)
Use the revoke endpoint to disable a token without deleting its record:
```bash
curl -X PATCH http://localhost:8080/admin/tokens/demo-client
```
After revocation, the same token will be rejected on `/api/*` calls.

## Delete a token record (demo cleanup)
The DELETE endpoint removes the DB record entirely. Use only for demo/reset:
```bash
curl -X DELETE http://localhost:8080/admin/tokens/demo-client
```
This hard-deletes the row; in real systems prefer revoke/disable over delete.

## Useful endpoints
- `GET /health` — public health check
- `GET /docs` — Swagger UI
- `GET /openapi` — OpenAPI JSON
- `POST /admin/issue-token` — issue/replace a token for `client_id`
- `GET /admin/tokens` — list all tokens
- `DELETE /admin/tokens/:client_id` — revoke token
- `GET /admin/usage/:client_id` — recent usage summary
- `GET /api/data` — protected sample data (requires Bearer token)
- `POST /api/data` — protected sample create (echoes payload)

## How tokens are stored
- Tokens are never stored in plaintext. Only a SHA-256 hash is stored in `api_tokens`.
- Validation: decode JWT → check `exp` and `type` → hash token → look up in DB → ensure active and not expired → log usage.
- Usage logs live in `token_usage_log` (endpoint, method, status, IP, timestamp).

## Troubleshooting (Docker beginners)
- **Port already in use (8080):** set `API_PORT` in `.env` to a free port, then `docker compose up --build` again.
- **Container won’t start DB:** make sure Docker Desktop/Engine is running. Retry `docker compose up --build`.
- **Schema not applied:** `init.sql` is mounted by Compose. If you changed it and need a clean DB, run `docker compose down -v` then `docker compose up --build`.
- **Environment changes not picked up:** if you edit `.env`, re-run `docker compose up --build`.
- **Need a fresh start:** `docker compose down -v` removes containers and the DB volume (data loss), then `docker compose up --build`.

## Production hardening checklist
- Set `DEMO_UNSAFE_ADMIN=false` (or remove it) and add authentication/authorization for all `/admin/*` routes.
- Use a strong `JWT_SECRET` and rotate regularly.
- Run Postgres with proper passwords, TLS, backups, and restricted network access.
- Consider shorter token lifetimes and refresh/rotation policies.
- Add rate limiting and monitoring on admin and API routes.
- Avoid logging raw tokens or secrets; keep logs minimal and sanitized.

## Reference commands (Docker)
- Start everything: `docker compose up --build`
- Start only DB: `docker compose up db`
- Rebuild containers after code changes: `docker compose build`

## Where to look in the code
- `api.jl` — the entire API (config, DB, JWT, middleware, routes, Swagger)
- `init.sql` — database schema (`api_tokens`, `token_usage_log`)
- `docker-compose.yml` — service definitions and environment wiring
- `AGENTS.md` — contributor guidance and coding conventions

## Safety reminder
This project is intentionally permissive for learning. Do **not** deploy the demo defaults to production. Lock down admin endpoints and secrets before exposing this API anywhere outside a local test environment.
