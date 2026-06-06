use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, response::Json};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use std::time::Instant;

use crate::auth::{Claims, AuthUser, JWT_SECRET};
use crate::model::*;
use crate::state::{AppState, CachedTasks, CACHE_TTL_SECS};

// ── Token helpers ─────────────────────────────────────────────────────────────

/// Generate a signed JWT with `kind` = "access", "refresh", or "challenge".
fn generate_token(user_id: i32, role: &str, kind: &str, expiry_secs: i64) -> Result<String, String> {
    let exp = (Utc::now().timestamp() + expiry_secs) as usize;
    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        kind: kind.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| e.to_string())
}

/// Generate a 6-digit OTP code.
fn generate_otp() -> String {
    let code: u32 = rand::thread_rng().gen_range(100_000..=999_999);
    code.to_string()
}

// ── create_user ───────────────────────────────────────────────────────────────

/// Register a new user (Admin or regular User)
#[utoipa::path(
    post,
    path = "/api/create-user",
    request_body = CreateUser,
    responses(
        (status = 200, description = "User created — login to get a JWT", body = MessageResponse),
        (status = 400, description = "Email already registered",           body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUser>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<MessageResponse>)> {
    // Duplicate email check
    let exists: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    if exists.is_some() {
        return Err(bad_request("Email already registered".to_string()));
    }

    // Hash password with Argon2
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| internal_error(e.to_string()))?
        .to_string();

    let role_str = body.role.to_string();

    sqlx::query(
        "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
    )
    .bind(&body.name)
    .bind(&body.email)
    .bind(&hashed)
    .bind(&role_str)
    .execute(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    Ok(Json(MessageResponse {
        message: format!("User '{}' created. Please login to receive a 2FA code.", body.name),
    }))
}

// ── login_user ────────────────────────────────────────────────────────────────

/// Initiate login — validates credentials then issues a 2FA challenge (no JWT yet)
#[utoipa::path(
    post,
    path = "/api/login-user",
    request_body = LoginUser,
    responses(
        (status = 200, description = "2FA challenge issued — call /api/verify-2fa with the code", body = LoginChallenge),
        (status = 401, description = "Invalid credentials", body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn login_user(
    State(state): State<AppState>,
    Json(body): Json<LoginUser>,
) -> Result<Json<LoginChallenge>, (StatusCode, Json<MessageResponse>)> {
    // 1. Look up user
    let user: Option<UserRow> =
        sqlx::query_as("SELECT id, name, email, password, role FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    let user = user.ok_or_else(|| unauthorized("Invalid email or password".to_string()))?;

    // 2. Verify password
    let parsed_hash =
        PasswordHash::new(&user.password).map_err(|e| internal_error(e.to_string()))?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| unauthorized("Invalid email or password".to_string()))?;

    // 3. Generate 6-digit OTP and store it in email_logs (expires in 5 min)
    let otp = generate_otp();
    sqlx::query(
        "INSERT INTO email_logs (user_id, email_code, expires_at, used)
         VALUES ($1, $2, NOW() + INTERVAL '5 minutes', false)",
    )
    .bind(user.id)
    .bind(&otp)
    .execute(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    // 4. Issue a short-lived challenge token (not an access token)
    let challenge_token = generate_token(user.id, &user.role, "challenge", 60 * 5)
        .map_err(|e| internal_error(e))?;

    // In production the OTP would be sent via email; we expose it in otp_hint for testing
    tracing::info!("[2FA] OTP for user {} ({}): {}", user.id, user.email, otp);

    Ok(Json(LoginChallenge {
        challenge_token,
        message: "2FA code sent. Call POST /api/verify-2fa with your code.".to_string(),
        otp_hint: otp,
    }))
}

// ── verify_two_fa ─────────────────────────────────────────────────────────────

/// Complete 2FA — submit the OTP code to receive a full JWT
#[utoipa::path(
    post,
    path = "/api/verify-2fa",
    request_body = VerifyTwoFa,
    responses(
        (status = 200, description = "2FA verified — JWT issued", body = UserResponse),
        (status = 401, description = "Invalid, expired, or reused code", body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn verify_two_fa(
    State(state): State<AppState>,
    Json(body): Json<VerifyTwoFa>,
) -> Result<Json<UserResponse>, (StatusCode, Json<MessageResponse>)> {
    // 1. Decode challenge token (must be kind=challenge, not expired)
    let claims = decode::<Claims>(
        &body.challenge_token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|_| unauthorized("Invalid or expired challenge token".to_string()))?
    .claims;

    if claims.kind != "challenge" {
        return Err(unauthorized("Expected a challenge token".to_string()));
    }

    let user_id = claims.sub;

    // 2. Look up the OTP in email_logs — must be for this user, unused, and not expired
    let log: Option<EmailLog> = sqlx::query_as(
        "SELECT id, user_id, email_code, expires_at, used, created_at
         FROM email_logs
         WHERE user_id = $1
           AND email_code = $2
           AND used = false
           AND expires_at > NOW()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .bind(&body.code)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    let log = log.ok_or_else(|| {
        unauthorized("Invalid, expired, or already-used 2FA code".to_string())
    })?;

    // 3. Mark the OTP as used (one-time-use enforcement)
    sqlx::query("UPDATE email_logs SET used = true WHERE id = $1")
        .bind(log.id)
        .execute(&state.pool)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    // 4. Load the user
    let user: UserRow =
        sqlx::query_as("SELECT id, name, email, password, role FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    // 5. Issue full access + refresh tokens
    let token_expiry = Utc::now().timestamp() + 60 * 60 * 24;
    let access_token =
        generate_token(user.id, &user.role, "access", 60 * 60 * 24)
            .map_err(|e| internal_error(e))?;
    let refresh_token =
        generate_token(user.id, &user.role, "refresh", 60 * 60 * 24 * 7)
            .map_err(|e| internal_error(e))?;

    Ok(Json(UserResponse {
        name: user.name,
        email: user.email,
        role: user.role,
        access_token,
        refresh_token,
        token_expiry,
    }))
}

// ── get_email_logs ────────────────────────────────────────────────────────────

/// List all 2FA email logs (Admin only)
#[utoipa::path(
    get,
    path = "/api/get-email-logs",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Email logs",      body = Vec<EmailLog>),
        (status = 403, description = "Admins only",     body = MessageResponse),
    ),
    tag = "Admin"
)]
pub async fn get_email_logs(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<EmailLog>>, (StatusCode, Json<MessageResponse>)> {
    require_admin(&auth)?;

    let logs: Vec<EmailLog> = sqlx::query_as(
        "SELECT id, user_id, email_code, expires_at, used, created_at FROM email_logs ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    Ok(Json(logs))
}

// ── create_task ───────────────────────────────────────────────────────────────

/// Create a new task (Admin only)
#[utoipa::path(
    post,
    path = "/api/create-task",
    security(("bearer_auth" = [])),
    request_body = CreateTask,
    responses(
        (status = 200, description = "Task created",  body = Tasks),
        (status = 403, description = "Admins only",   body = MessageResponse),
    ),
    tag = "Tasks"
)]
pub async fn create_task(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<CreateTask>,
) -> Result<Json<Tasks>, (StatusCode, Json<MessageResponse>)> {
    require_admin(&auth)?;

    let priority_str = match body.priority {
        Priority::High => "high",
        Priority::Medium => "medium",
        Priority::Low => "low",
    };

    let task: Tasks = sqlx::query_as(
        "INSERT INTO tasks (title, description, task_status, priority, assigned_to)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, title, description, task_status, priority, assigned_to, created_at, updated_at",
    )
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.task_status)
    .bind(priority_str)
    .bind(body.assigned_to)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    // If the task was created with an assignee, invalidate their cache
    if let Some(assignee_id) = task.assigned_to {
        state.invalidate_cache(assignee_id);
    }

    Ok(Json(task))
}

// ── task_assign ───────────────────────────────────────────────────────────────

/// Assign a task to a user (Admin only) — invalidates the assignee's task cache
#[utoipa::path(
    post,
    path = "/api/task-assign",
    security(("bearer_auth" = [])),
    request_body = AssignTask,
    responses(
        (status = 200, description = "Task assigned and cache invalidated", body = Tasks),
        (status = 403, description = "Admins only",                         body = MessageResponse),
        (status = 404, description = "Task not found",                      body = MessageResponse),
    ),
    tag = "Tasks"
)]
pub async fn task_assign(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<AssignTask>,
) -> Result<Json<Tasks>, (StatusCode, Json<MessageResponse>)> {
    require_admin(&auth)?;

    // Capture the *old* assignee so we can invalidate their cache too
    let old_assignee: Option<(Option<i32>,)> =
        sqlx::query_as("SELECT assigned_to FROM tasks WHERE id = $1")
            .bind(body.task_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    if old_assignee.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(MessageResponse {
                message: format!("Task {} not found", body.task_id),
            }),
        ));
    }

    let task: Tasks = sqlx::query_as(
        "UPDATE tasks SET assigned_to = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING id, title, description, task_status, priority, assigned_to, created_at, updated_at",
    )
    .bind(body.assigned_to)
    .bind(body.task_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    // Invalidate cache for the new assignee
    state.invalidate_cache(body.assigned_to);

    // Also invalidate the previous assignee if different
    if let Some((Some(prev),)) = old_assignee {
        if prev != body.assigned_to {
            state.invalidate_cache(prev);
        }
    }

    Ok(Json(task))
}

// ── view_my_tasks ─────────────────────────────────────────────────────────────

/// View all tasks assigned to the authenticated user (with in-memory caching)
#[utoipa::path(
    get,
    path = "/api/view-my-tasks",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Tasks for the authenticated user (cache_hit shows whether result was served from cache)", body = TasksResponse),
    ),
    tag = "Tasks"
)]
pub async fn view_my_tasks(
    auth: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<TasksResponse>, (StatusCode, Json<MessageResponse>)> {
    let user_id = auth.user_id;

    // ── Check cache ──────────────────────────────────────────────────────────
    {
        let guard = state.cache.lock().map_err(|_| internal_error("Cache lock poisoned".to_string()))?;
        if let Some(entry) = guard.get(&user_id) {
            if entry.cached_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Json(TasksResponse {
                    tasks: entry.tasks.clone(),
                    cache_hit: true,
                }));
            }
        }
    } // lock released

    // ── Cache miss — query DB ────────────────────────────────────────────────
    let tasks: Vec<Tasks> = sqlx::query_as(
        "SELECT id, title, description, task_status, priority, assigned_to, created_at, updated_at
         FROM tasks
         WHERE assigned_to = $1
         ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    // ── Store in cache ────────────────────────────────────────────────────────
    {
        let mut guard = state.cache.lock().map_err(|_| internal_error("Cache lock poisoned".to_string()))?;
        guard.insert(
            user_id,
            CachedTasks {
                tasks: tasks.clone(),
                cached_at: Instant::now(),
            },
        );
    }

    Ok(Json(TasksResponse {
        tasks,
        cache_hit: false,
    }))
}

// ── Error / guard helpers ─────────────────────────────────────────────────────

/// Require the authenticated user to have the "admin" role.
fn require_admin(auth: &AuthUser) -> Result<(), (StatusCode, Json<MessageResponse>)> {
    if auth.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: "This action requires the admin role".to_string(),
            }),
        ));
    }
    Ok(())
}

fn bad_request(msg: String) -> (StatusCode, Json<MessageResponse>) {
    (StatusCode::BAD_REQUEST, Json(MessageResponse { message: msg }))
}

fn unauthorized(msg: String) -> (StatusCode, Json<MessageResponse>) {
    (StatusCode::UNAUTHORIZED, Json(MessageResponse { message: msg }))
}

fn internal_error(msg: String) -> (StatusCode, Json<MessageResponse>) {
    tracing::error!("Internal error: {}", msg);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(MessageResponse {
            message: "Internal server error".to_string(),
        }),
    )
}
