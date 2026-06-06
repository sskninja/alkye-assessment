# AI Usage Summary — alkye_backend

> **Project:** Alkye Backend (Rust / Axum / PostgreSQL)
> **AI Tool:** Antigravity (Google DeepMind)
> **Date:** 2026-06-06

---

## What the AI Did

### 1. Project Diagnosis & Fix


| File | Issues Found | Fix Applied |
|------|-------------|-------------|

| `src/model.rs` | Wrong import paths (`crate::chrono`, `crate::serde`), non-PascalCase enum, missing structs |  |
| `src/permisiion.rs` | Referenced non-existent `UserType`, typo in field name |
| `src/user_management.rs` | String concatenation SQL injection, unclosed braces, wrong function names |
| `src/main.rs` | Empty main, declared non-existent `routes` module |  |
| `src/management_routes.rs` | Wrong handler signatures, incompatible state type |  |
| `migrations/*.sql` | MSSQL syntax (`IDENTITY`, `NVARCHAR`, `GETDATE()`) |  |

---

### 2.  Files Fixed

| File | Purpose |
|------|---------|
| `src/auth.rs` | JWT `Claims` struct + `AuthUser` Axum extractor (reads `Authorization: Bearer`) |
| `src/state.rs` | `AppState` with `PgPool` + `Arc<Mutex<HashMap>>` in-memory task cache |
| `migrations/20260606075000_add_2fa_to_email_logs.sql` | Added `expires_at` and `used` columns to `email_logs` for 2FA |


---

### 3. Features Checked

#### 2FA Login Flow
- `POST /api/login-user` — validates credentials, generates a 6-digit OTP stored in `email_logs`, returns a short-lived **challenge_token** (no JWT)
- `POST /api/verify-2fa` — validates challenge token + OTP (checks: not expired, not reused), marks OTP as `used`, issues full **access_token** + **refresh_token**

#### JWT Token Types
- `kind = "challenge"` — temporary, only valid for `/verify-2fa`
- `kind = "access"` — full access token for protected routes
- `kind = "refresh"` — long-lived refresh token

#### Role-Based Access Control
- `AuthUser` extractor automatically reads and validates the Bearer token on every protected handler
- `require_admin()` guard rejects non-admin roles with `403 Forbidden`
- James Bond (`user` role) is blocked from `create_task` and `task_assign`

#### In-Memory Task Cache
- `view_my_tasks` checks an in-memory `HashMap<user_id, CachedTasks>` (TTL = 60s)
- First call → DB query, stores result, returns `cache_hit: false`
- Second call (within 60s) → returns cached result with `cache_hit: true`
- `task_assign` invalidates the affected user's cache entry immediately

#### Swagger UI
- Full OpenAPI spec registered via `utoipa`
- Bearer JWT security scheme shown in Swagger
- Available at `http://localhost:3000/swagger-ui`

---

### 4. Acceptance Criteria Coverage

| # | Criterion | Implementation |
|---|-----------|----------------|
| 1 | Admin and James Bond can be created | `POST /api/create-user` with `role: "admin"` or `"user"` |
| 2 | Login returns 2FA challenge, not JWT | `POST /api/login-user` → `LoginChallenge { challenge_token, otp_hint }` |
| 3 | Correct 2FA code returns JWT | `POST /api/verify-2fa` → `UserResponse { access_token, … }` |
| 4 | Incorrect/expired/reused codes rejected | DB query filters `used=false AND expires_at > NOW()`, marks used after first use |
| 5 | Admin can create 5 tasks | `POST /api/create-task` with admin JWT — no hard limit, role-gated |
| 6 | Admin can assign 3 tasks to James Bond | `POST /api/task-assign` with admin JWT |
| 7 | James Bond cannot create a task | `require_admin()` returns `403` for `user` role |
| 8 | James Bond views exactly his 3 assigned tasks | `GET /api/view-my-tasks` queries `WHERE assigned_to = <user_id>` from JWT |
| 9 | Second call shows `cache_hit: true` | In-memory cache with TTL in `AppState` |
| 10 | Assignment invalidates cache | `task_assign` calls `state.invalidate_cache(assignee_id)` |

---


Server runs on `http://localhost:3000` · Swagger at `http://localhost:3000/swagger-ui`

---


