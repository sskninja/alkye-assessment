pub mod auth;
pub mod management_routes;
pub mod model;
pub mod permisiion;
pub mod state;
pub mod user_management;

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::model::*;
use crate::state::AppState;

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(
        user_management::create_user,
        user_management::login_user,
        user_management::verify_two_fa,
        user_management::get_email_logs,
        user_management::create_task,
        user_management::task_assign,
        user_management::view_my_tasks,
    ),
    components(
        schemas(
            // Request bodies
            CreateUser, LoginUser, VerifyTwoFa, CreateTask, AssignTask,
            // Responses
            LoginChallenge, UserResponse, TasksResponse, MessageResponse,
            // Row types
            Tasks, EmailLog,
            // Enums
            UserType, Priority,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Users", description = "User registration & 2FA authentication"),
        (name = "Tasks", description = "Task management (JWT required)"),
        (name = "Admin", description = "Admin-only endpoints (JWT + admin role required)"),
    ),
    info(
        title = "Alkye Backend API",
        version = "0.1.0",
        description = "REST API for Alkye task-management platform.\n\n\
            ## Auth flow\n\
            1. `POST /api/create-user` — register\n\
            2. `POST /api/login-user` — get a **challenge_token** + OTP\n\
            3. `POST /api/verify-2fa` — submit OTP → receive **access_token**\n\
            4. Use `Authorization: Bearer <access_token>` on protected routes",
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Load .env file (silently ignored if absent)
    dotenvy::dotenv().ok();

    // Structured logging
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

    tracing::info!("✅ Connected to database");

    // Run migrations automatically on startup
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("✅ Migrations applied");

    // Build shared app state (pool + in-memory cache)
    let state = AppState::new(pool);

    // CORS — open for local development
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the router
    let app = Router::new()
        // Swagger UI at /swagger-ui
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // All API routes under /api
        .nest("/api", management_routes::get_user_routes())
        .layer(cors)
        .with_state(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("🚀 Server listening on http://{}", addr);
    tracing::info!("📖 Swagger UI      http://{}/swagger-ui", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to port 3000");

    axum::serve(listener, app).await.expect("Server crashed");
}
