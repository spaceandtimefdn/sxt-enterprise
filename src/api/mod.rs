//! The HTTP API: create tables, insert rows, and run proved queries.
//!
//! Every handler locks the shared [`Db`] for its own request; a real verifier must pin
//! commitments independently rather than trust the ones a response happens to include.

use alloc::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use parking_lot::Mutex;
use proof_of_sql::proof_primitive::hyperkzg::HyperKZGPublicSetupOwned;

use crate::db::Db;

mod health;
mod query;
mod rows;
mod tables;

pub use query::{QueriedTable, QueryError, QueryResult};
pub use rows::RowsError;
pub use tables::TableError;

/// Shared state every handler operates on.
#[derive(Clone)]
pub struct AppState {
    /// The database every handler reads and writes.
    db: Arc<Mutex<Db>>,
    /// Powers of tau used to prove and commit to inserted data.
    setup: Arc<HyperKZGPublicSetupOwned>,
}

impl AppState {
    /// Builds the shared state handlers operate on.
    #[must_use]
    pub fn new(db: Db, setup: HyperKZGPublicSetupOwned) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            setup: Arc::new(setup),
        }
    }
}

/// Builds the router, ready to serve or to drive with `tower::ServiceExt::oneshot` in tests.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .route("/tables", get(tables::list).post(tables::create))
        .route("/tables/{table}", get(tables::show))
        .route("/tables/{table}/rows", post(rows::insert))
        .route("/query", post(query::query))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::{AppState, router};

    pub(super) fn test_setup() -> proof_of_sql::proof_primitive::hyperkzg::HyperKZGPublicSetupOwned
    {
        crate::setup::prover::from_ptau_url(
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau",
            4,
        )
        .unwrap()
    }

    pub(super) fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(dir.path().to_path_buf()).unwrap();
        (dir, AppState::new(db, test_setup()))
    }

    /// Overwrites `table`'s commitment with garbage, so any read of it fails with a
    /// [`crate::db::DbError::Decode`] rather than any of a handler's expected failure modes.
    pub(super) fn corrupt_commitment(dir: &tempfile::TempDir, table: &str) {
        std::fs::write(dir.path().join(table).join("table.commit"), [0xff_u8; 4]).unwrap();
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let (_dir, state) = test_state();
        let response = router(state)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
