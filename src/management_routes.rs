use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;
use crate::user_management;

pub fn get_user_routes() -> Router<AppState> {
    Router::new()
        // ── Auth (no JWT required) ──────────────────────────────────────────
        .route("/create-user",              post(user_management::create_user))
        .route("/login-user",               post(user_management::login_user))
        .route("/verify-2fa",               post(user_management::verify_two_fa))
        // ── Authenticated (JWT required) ────────────────────────────────────
        .route("/get-email-logs",           get(user_management::get_email_logs))
        .route("/create-task",              post(user_management::create_task))
        .route("/task-assign",              post(user_management::task_assign))
        .route("/view-my-tasks",            get(user_management::view_my_tasks))
}
