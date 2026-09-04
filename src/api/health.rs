//! `GET /health`: a liveness check.

use axum::http::StatusCode;

/// Always reports healthy: if the process is serving requests, it is up.
pub async fn health() -> StatusCode {
    StatusCode::OK
}
