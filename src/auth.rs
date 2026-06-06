//! JWT authentication extractor for Axum handlers.
//!
//! Usage in a handler:
//! ```rust
//! pub async fn my_handler(auth: AuthUser, ...) -> ...
//! ```

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::model::MessageResponse;

/// Secret shared between token generation and validation.
/// In production load from `JWT_SECRET` env var.
pub const JWT_SECRET: &[u8] = b"alkye_super_secret_change_in_prod";

// ── Claims ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — user ID
    pub sub: i32,
    pub role: String,
    /// "challenge" | "access" | "refresh"
    pub kind: String,
    pub exp: usize,
}

// ── AuthUser extractor ────────────────────────────────────────────────────────

/// Extracts and validates a full (non-challenge) JWT from `Authorization: Bearer <token>`.
/// Rejects missing tokens, invalid tokens, and challenge tokens.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i32,
    pub role: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(MessageResponse {
                        message: "Missing Authorization header".to_string(),
                    }),
                )
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Authorization header must be `Bearer <token>`".to_string(),
                }),
            )
        })?;

        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: format!("Invalid or expired token: {}", e),
                }),
            )
        })?
        .claims;

        // Reject challenge tokens — they are not access tokens
        if claims.kind != "access" {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Provide an access token, not a challenge token".to_string(),
                }),
            ));
        }

        Ok(AuthUser {
            user_id: claims.sub,
            role: claims.role,
        })
    }
}
