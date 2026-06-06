use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, response::Json};
use chrono::Utc;
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::model::*;
use crate::permisiion::check_permission;

// ── JWT helpers ──────────────────────────────────────────────────────────────

const JWT_SECRET: &[u8] = b"alkye_super_secret_change_in_prod";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32, // user id
    role: String,
    exp: usize, // expiry timestamp
}

fn generate_token(user_id: i32, role: &str, expiry_secs: i64) -> Result<String, String> {
    let expiration = (Utc::now().timestamp() + expiry_secs) as usize;
    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        exp: expiration,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| e.to_string())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Register a new user
#[utoipa::path(
    post,
    path = "/api/create-user",
    request_body = CreateUser,
    responses(
        (status = 200, description = "User created successfully", body = UserResponse),
        (status = 400, description = "Bad request", body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn create_user(
    State(pool): State<PgPool>,
    Json(body): Json<CreateUser>,
) -> Result<Json<UserResponse>, (StatusCode, Json<MessageResponse>)> {
    let permission = check_permission(&body.role);

    // Check duplicate email
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_optional(&pool)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    if exists.is_some() {
        return Err(bad_request("Email already registered".to_string()));
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let hashed = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| internal_error(e.to_string()))?
        .to_string();

    let role_str = body.role.to_string();
    let email_code =
        generate_token(body.id, &body.role, 60 * 60 * 24).map_err(|e| internal_error(e))?;

    let user: UserRow = sqlx::query_as(
        "INSERT INTO users (name, email, password, role, email_code) VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, email, password, role, email_code",
    )
    .bind(&body.name)
    .bind(&body.email)
    .bind(&hashed)
    .bind(&role_str)
    .bind(&email_code)
    .fetch_one(&pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    let token_expiry = Utc::now().timestamp() + 60 * 60 * 24; // 24 h
    let access_token =
        generate_token(user.id, &user.role, 60 * 60 * 24).map_err(|e| internal_error(e))?;
    let refresh_token =
        generate_token(user.id, &user.role, 60 * 60 * 24 * 7).map_err(|e| internal_error(e))?;

    Ok(Json(UserResponse {
        name: user.name,
        email: user.email,
        role: user.role,
        access_token,
        refresh_token,
        token_expiry,
    }))
}

/// Login an existing user
#[utoipa::path(
    post,
    path = "/api/login-user",
    request_body = LoginUser,
    responses(
        (status = 200, description = "Login successful", body = UserResponse),
        (status = 401, description = "Invalid credentials", body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn login_user(
    State(pool): State<PgPool>,
    Json(body): Json<LoginUser>,
) -> Result<Json<UserResponse>, (StatusCode, Json<MessageResponse>)> {
    let user: Option<UserRow> =
        sqlx::query_as("SELECT id, name, email, password, role FROM users WHERE email = $1")
            .bind(&body.email)
            .fetch_optional(&pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    let user = user.ok_or_else(|| bad_request("Invalid email or password".to_string()))?;

    let parsed_hash =
        PasswordHash::new(&user.password).map_err(|e| internal_error(e.to_string()))?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| bad_request("Invalid email or password".to_string()))?;

    let expiry_secs = if body.remember_me {
        60 * 60 * 24 * 30 // 30 days
    } else {
        60 * 60 * 24 // 24 h
    };

    let token_expiry = Utc::now().timestamp() + expiry_secs;
    let access_token =
        generate_token(user.id, &user.role, expiry_secs).map_err(|e| internal_error(e))?;
    let refresh_token =
        generate_token(user.id, &user.role, 60 * 60 * 24 * 7).map_err(|e| internal_error(e))?;

    Ok(Json(UserResponse {
        name: user.name,
        email: user.email,
        role: user.role,
        access_token,
        refresh_token,
        token_expiry,
    }))
}

/// Get all email verification logs (admin only)
#[utoipa::path(
    get,
    path = "/api/get-email-logs",
    responses(
        (status = 200, description = "Email logs", body = Vec<EmailLog>),
        (status = 500, description = "Server error", body = MessageResponse),
    ),
    tag = "Admin"
)]
pub async fn get_email_logs(
    State(pool): State<PgPool>,
) -> Result<Json<Vec<EmailLog>>, (StatusCode, Json<MessageResponse>)> {
    let logs: Vec<EmailLog> =
        sqlx::query_as("SELECT id, user_id, email_code, created_at FROM email_logs")
            .fetch_all(&pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;
    Ok(Json(logs))
}

/// Verify a user's email with a verification code
#[utoipa::path(
    post,
    path = "/api/authentication-verification",
    params(("code" = String, Query, description = "Email verification code")),
    responses(
        (status = 200, description = "Verified", body = UserResponse),
        (status = 400, description = "Invalid code", body = MessageResponse),
    ),
    tag = "Users"
)]
pub async fn authentication_verification(
    State(pool): State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<UserResponse>, (StatusCode, Json<MessageResponse>)> {
    let code = params
        .get("code")
        .ok_or_else(|| bad_request("Missing `code` query parameter".to_string()))?;

    let log: EmailLog = sqlx::query_as(
        "SELECT id, user_id, email_code, created_at FROM email_logs WHERE email_code = $1",
    )
    .bind(code)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?
    .ok_or_else(|| bad_request("Invalid or expired code".to_string()))?;

    let user: UserRow =
        sqlx::query_as("SELECT id, name, email, password, role FROM users WHERE id = $1")
            .bind(log.user_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| internal_error(e.to_string()))?;

    let token_expiry = Utc::now().timestamp() + 60 * 5;
    let access_token =
        generate_token(user.id, &user.role, 60 * 5).map_err(|e| internal_error(e))?;
    let refresh_token =
        generate_token(user.id, &user.role, 60 * 60 * 24 * 7).map_err(|e| internal_error(e))?;

    Ok(Json(UserResponse {
        name: user.name,
        email: user.email,
        role: user.role,
        access_token,
        refresh_token,
        token_expiry,
    }))
}

/// Create a new task (admin only)
#[utoipa::path(
    post,
    path = "/api/create-task",
    request_body = CreateTask,
    responses(
        (status = 200, description = "Task created", body = Tasks),
        (status = 403, description = "Forbidden", body = MessageResponse),
    ),
    tag = "Tasks"
)]
pub async fn create_task(
    State(pool): State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Json(body): Json<CreateTask>,
) -> Result<Json<Tasks>, (StatusCode, Json<MessageResponse>)> {
    let role = params
        .get("role")
        .ok_or_else(|| bad_request("Missing `role` query parameter".to_string()))?;

    if role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: "Only admins can create tasks".to_string(),
            }),
        ));
    }

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
    .fetch_one(&pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    Ok(Json(task))
}

/// Assign a task to a user (admin only)
#[utoipa::path(
    post,
    path = "/api/task-assign",
    request_body = AssignTask,
    responses(
        (status = 200, description = "Task assigned", body = Tasks),
        (status = 403, description = "Forbidden", body = MessageResponse),
    ),
    tag = "Tasks"
)]
pub async fn task_assign(
    State(pool): State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Json(body): Json<AssignTask>,
) -> Result<Json<Tasks>, (StatusCode, Json<MessageResponse>)> {
    let role = params
        .get("role")
        .ok_or_else(|| bad_request("Missing `role` query parameter".to_string()))?;

    if role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MessageResponse {
                message: "Only admins can assign tasks".to_string(),
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
    .fetch_one(&pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    Ok(Json(task))
}

/// View a specific task by ID
#[utoipa::path(
    get,
    path = "/api/view-my-tasks",
    params(("task_id" = i32, Query, description = "Task ID")),
    responses(
        (status = 200, description = "Task found", body = Tasks),
        (status = 404, description = "Task not found", body = MessageResponse),
    ),
    tag = "Tasks"
)]
pub async fn view_my_tasks(
    State(pool): State<PgPool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Tasks>, (StatusCode, Json<MessageResponse>)> {
    let task_id: i32 = params
        .get("task_id")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad_request("Missing or invalid `task_id` query parameter".to_string()))?;

    let task: Option<Tasks> = sqlx::query_as(
        "SELECT id, title, description, task_status, priority, assigned_to, created_at, updated_at
         FROM tasks WHERE id = $1",
    )
    .bind(task_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error(e.to_string()))?;

    task.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(MessageResponse {
                message: "Task not found".to_string(),
            }),
        )
    })
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn bad_request(msg: String) -> (StatusCode, Json<MessageResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(MessageResponse { message: msg }),
    )
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
