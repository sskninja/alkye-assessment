use axum::{Router, routing::{get, post}};
use sqlx::PgPool;

use crate::user_management;

pub fn get_user_routes() -> Router<PgPool> {
    Router::new()
        .route("/create-user", post(user_management::create_user))
        .route("/login-user", post(user_management::login_user))
        .route("/get-email-logs", get(user_management::get_email_logs))
        .route(
            "/authentication-verification",
            get(user_management::authentication_verification),
        )
        .route("/create-task", post(user_management::create_task))
        .route("/task-assign", post(user_management::task_assign))
        .route("/view-my-tasks", get(user_management::view_my_tasks))
}
