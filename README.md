# Alkye Backend

A REST API for the Alkye task-management platform, built with **Rust**, **Axum**, and **PostgreSQL**.

Features two-factor authentication (2FA), JWT-based role access control, and an in-memory task cache with automatic invalidation.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust 2021 |
| Web Framework | Axum 0.7 |
| Database | PostgreSQL (via SQLx 0.8) |
| Auth | JWT (jsonwebtoken 9) + Argon2 password hashing |
| API Docs | utoipa + Swagger UI |
| Migrations | SQLx built-in migrator |
| Config | dotenvy (.env) |
| Logging | tracing + tracing-subscriber |

---

## Prerequisites

- Rust (stable, 2021 edition) — https://rustup.rs
- PostgreSQL running locally
- `sqlx-cli` (optional, for manual migrations)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/sskninja/alkye-assessment.git
cd alkye-assessment
```

### 2. Create the database

```bash
psql -U postgres -c "CREATE DATABASE alkye_db;"
```

### 3. Configure environment

```bash
cp .env.example .env
```

`.env` defaults (ready to use as-is for local dev):

```env
DATABASE_URL=postgres://postgres@localhost/alkye_db
JWT_SECRET=alkye_super_secret_change_in_prod
HOST=0.0.0.0
PORT=3000
RUST_LOG=alkye_backend=debug,tower_http=debug
```

### 4. Run the server

```bash
cargo run
```

Migrations are applied **automatically on startup**. The server binds to `http://localhost:3000`.

---

## API Documentation

Interactive Swagger UI is available at:

```
http://localhost:3000/swagger-ui
```

---

## Authentication Flow

```
POST /api/create-user          →  Register (role: "admin" | "user")
POST /api/login-user           →  Returns challenge_token + OTP code (no JWT yet)
POST /api/verify-2fa           →  Submit OTP → receive access_token + refresh_token
```

Use the access token on all protected routes:

```
Authorization: Bearer <access_token>
```

### JWT Token Types

| Kind | Validity | Purpose |
|------|----------|---------|
| `challenge` | 5 minutes | Identifies a pending 2FA login — not an access token |
| `access` | 24 hours | Grants access to protected routes |
| `refresh` | 7 days | Used to obtain new access tokens |

---

## Endpoints

### Public (no JWT required)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/create-user` | Register a new user |
| `POST` | `/api/login-user` | Start login — returns 2FA challenge |
| `POST` | `/api/verify-2fa` | Complete 2FA — returns JWT |

### Authenticated (JWT required)

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/api/view-my-tasks` | any | List tasks assigned to the caller |
| `POST` | `/api/create-task` | admin | Create a new task |
| `POST` | `/api/task-assign` | admin | Assign a task to a user |
| `GET` | `/api/get-email-logs` | admin | View all 2FA OTP logs |

---

## 2FA Security

- Login generates a **6-digit OTP** stored in `email_logs` with a 5-minute expiry
- OTPs are **single-use** — marked `used = true` after first successful verification
- Reused, expired, or incorrect codes are rejected with `401`
- The `otp_hint` field in the login response simulates email delivery (remove in production)

---

## Task Cache

`GET /api/view-my-tasks` uses an **in-memory per-user cache** (TTL = 60 seconds):

```json
{
  "tasks": [...],
  "cache_hit": false   ← first call hits the database
}
```

```json
{
  "tasks": [...],
  "cache_hit": true    ← subsequent calls within 60s are served from cache
}
```

Cache is **automatically invalidated** when a task is assigned or reassigned via `POST /api/task-assign`.

---

## Project Structure

```
alkye_backend/
├── src/
│   ├── main.rs              # Server bootstrap, OpenAPI spec, routing
│   ├── auth.rs              # JWT Claims + AuthUser Axum extractor
│   ├── state.rs             # AppState (PgPool + in-memory cache)
│   ├── model.rs             # All request/response/DB structs
│   ├── user_management.rs   # All handler implementations
│   ├── management_routes.rs # Route registration
│   └── permisiion.rs        # Role permission helpers
├── migrations/
│   ├── 20260606065154_task_management_schema.sql   # Core schema
│   └── 20260606075000_add_2fa_to_email_logs.sql   # 2FA columns
├── .env                     # Local config (gitignored)
├── .env.example             # Config template
├── ai_usage.md              # AI assistance log
└── Cargo.toml
```

---

## Role-Based Access

| Action | Admin | User |
|--------|-------|------|
| Register / Login | ✅ | ✅ |
| View own tasks | ✅ | ✅ |
| Create task | ✅ | ❌ 403 |
| Assign task | ✅ | ❌ 403 |
| View email logs | ✅ | ❌ 403 |

---

## Acceptance Criteria

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Admin and regular user can be created | ✅ |
| 2 | Login does **not** return a JWT immediately | ✅ — returns `challenge_token` |
| 3 | Correct 2FA code returns a full JWT | ✅ |
| 4 | Invalid / expired / reused codes are rejected | ✅ |
| 5 | Admin can create tasks (e.g. 5) | ✅ |
| 6 | Admin can assign tasks to another user (e.g. 3) | ✅ |
| 7 | Non-admin cannot create a task | ✅ — `403 Forbidden` |
| 8 | User sees only their assigned tasks | ✅ — filtered by `assigned_to` from JWT |
| 9 | Second `view-my-tasks` call shows `cache_hit: true` | ✅ |
| 10 | Assignment invalidates the affected user's cache | ✅ |

---

## License

MIT
