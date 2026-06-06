use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── User types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
pub enum UserType {
    Admin,
    User,
}

impl std::fmt::Display for UserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserType::Admin => write!(f, "admin"),
            UserType::User => write!(f, "user"),
        }
    }
}

// ── Task priority ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
pub enum Priority {
    High,
    Medium,
    Low,
}

// ── Request / response models ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    pub role: UserType,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateTask {
    pub title: String,
    pub description: Option<String>,
    pub task_status: String,
    pub priority: Priority,
    pub assigned_to: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AssignTask {
    pub task_id: i32,
    pub assigned_to: i32,
}

// ── Database row models ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct UserRow {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub password: String,
    pub email_code: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct Tasks {
    pub id: i32,
    pub title: String,
    pub description: Option<String>,
    pub task_status: String,
    pub priority: String,
    pub assigned_to: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct EmailLog {
    pub id: i32,
    pub user_id: i32,
    pub email_code: String,
    pub created_at: DateTime<Utc>,
}

// ── API responses ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    pub name: String,
    pub email: String,
    pub role: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_expiry: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}
