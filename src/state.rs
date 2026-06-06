//! Shared application state threaded through all Axum handlers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use sqlx::PgPool;

use crate::model::Tasks;

// ── Cache entry ───────────────────────────────────────────────────────────────

/// One cached result for a given user's assigned tasks.
pub struct CachedTasks {
    pub tasks: Vec<Tasks>,
    pub cached_at: Instant,
}

/// TTL for the task cache (60 seconds)
pub const CACHE_TTL_SECS: u64 = 60;

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// In-memory task cache: key = assignee user_id
    pub cache: Arc<Mutex<HashMap<i32, CachedTasks>>>,
}

impl AppState {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Invalidate the task cache for a specific user (called after assignment changes).
    pub fn invalidate_cache(&self, user_id: i32) {
        if let Ok(mut guard) = self.cache.lock() {
            guard.remove(&user_id);
        }
    }
}
