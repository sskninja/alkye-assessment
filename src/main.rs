pub mod management_routes;
pub mod model;
pub mod permisiion;
pub mod user_management;

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::model::*;

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(
        user_management::create_user,
        user_management::login_user,
        user_management::get_email_logs,
        user_management::authentication_verification,
        user_management::create_task,
        user_management::task_assign,
        user_management::view_my_tasks,
    ),
    components(
        schemas(
            CreateUser, LoginUser, CreateTask, AssignTask,
            UserResponse, MessageResponse, Tasks, EmailLog,
            UserType, Priority,
        )
    ),
    tags(
        (name = "Users", description = "User authentication & management"),
        (name = "Tasks", description = "Task management endpoints"),
        (name = "Admin", description = "Admin-only endpoints"),
    ),
    info(
        title = "Alkye Backend API",
        version = "0.1.0",
        description = "REST API for Alkye task management platform",
    )
)]
struct ApiDoc;

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Load .env file (ignores error if file is absent)
    dotenvy::dotenv().ok();

    // Tracing / logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "alkye_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database connection pool
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (check your .env file)");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    tracing::info!(" Connected to database");

    // Run migrations automatically
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("✅ Migrations applied");

    // CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the router
    let app = Router::new()
        // Swagger UI at /swagger-ui
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // API routes under /api
        .nest("/api", management_routes::get_user_routes())
        .layer(cors)
        .with_state(pool);

    let addr = "0.0.0.0:3000";
    tracing::info!("🚀 Server listening on http://{}", addr);
    tracing::info!("📖 Swagger UI at  http://{}/swagger-ui", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to port 3000");

    axum::serve(listener, app).await.expect("Server crashed");
}
