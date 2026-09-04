//! `POST /tables/{table}/rows`.

use arrow::json::ReaderBuilder;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use proof_of_sql::base::database::TableRef;
use serde::Deserialize;
use serde_json::Value;

use super::AppState;
use crate::db::DbError;

/// Failure to insert rows over the HTTP API.
#[derive(Debug, thiserror::Error)]
pub enum RowsError {
    /// The table reference in the request path could not be parsed.
    #[error(transparent)]
    TableName(#[from] proof_of_sql::base::database::ParseError),
    /// The rows could not be decoded against the table's schema.
    #[error(transparent)]
    Decode(#[from] arrow::error::ArrowError),
    /// The rows could not be inserted.
    #[error(transparent)]
    Db(#[from] DbError),
}

impl IntoResponse for RowsError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Db(DbError::NotFound(_)) => StatusCode::NOT_FOUND,
            Self::TableName(_) | Self::Decode(_) | Self::Db(DbError::SchemaMismatch) => {
                StatusCode::BAD_REQUEST
            }
            Self::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

/// The body of `POST /tables/{table}/rows`.
#[derive(Debug, Deserialize)]
pub struct InsertRows {
    /// Each row, as a JSON object keyed by column name.
    rows: Vec<Value>,
}

/// Appends `rows` to `table`.
///
/// # Errors
/// Fails if `table` cannot be parsed, does not exist, or `rows` does not match its schema.
pub async fn insert(
    State(state): State<AppState>,
    Path(table): Path<String>,
    Json(body): Json<InsertRows>,
) -> Result<StatusCode, RowsError> {
    let table_ref: TableRef = table.parse()?;
    let db = state.db.lock();
    let schema = db.schema(&table_ref)?;

    let mut decoder = ReaderBuilder::new(schema.clone()).build_decoder()?;
    decoder.serialize(&body.rows)?;
    let batch = decoder
        .flush()?
        .unwrap_or_else(|| arrow::array::RecordBatch::new_empty(schema));

    db.insert(&table_ref, &batch, &state.setup[..])?;
    Ok(StatusCode::CREATED)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::super::router;
    use super::super::tests::{corrupt_commitment, test_state};

    async fn create_items_table(state: &super::AppState) {
        router(state.clone())
            .oneshot(
                Request::post("/tables")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"table":"db.items","columns":[{"name":"id","type":"BIGINT"},{"name":"label","type":"VARCHAR"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_empty_row_list_is_accepted() {
        let (_dir, state) = test_state();
        create_items_table(&state).await;

        let response = router(state)
            .oneshot(
                Request::post("/tables/db.items/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn rows_can_be_inserted() {
        let (_dir, state) = test_state();
        create_items_table(&state).await;

        let response = router(state)
            .oneshot(
                Request::post("/tables/db.items/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"rows":[{"id":1,"label":"one"},{"id":2,"label":"two"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn inserting_into_an_unknown_table_is_not_found() {
        let (_dir, state) = test_state();

        let response = router(state)
            .oneshot(
                Request::post("/tables/db.missing/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":[{"id":1}]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_mismatched_row_is_rejected() {
        let (_dir, state) = test_state();
        create_items_table(&state).await;

        let response = router(state)
            .oneshot(
                Request::post("/tables/db.items/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":[{"id":"not a number"}]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_corrupt_commitment_is_an_internal_error() {
        let (dir, state) = test_state();
        create_items_table(&state).await;
        corrupt_commitment(&dir, "db.items");

        let response = router(state)
            .oneshot(
                Request::post("/tables/db.items/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":[{"id":1,"label":"one"}]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
