//! `POST /query`.

use std::collections::HashMap;

use arrow::array::RecordBatch;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::AppState;
use super::tables::encode_commitment;
use crate::db::DbError;
use crate::prove::{self, ProveError, prove};

/// Failure to prove a query over the HTTP API.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The query could not be proved.
    #[error(transparent)]
    Prove(#[from] ProveError),
    /// The proved result could not be converted to JSON rows.
    #[error(transparent)]
    Arrow(#[from] arrow::error::ArrowError),
    /// The proof or a commitment could not be encoded.
    #[error(transparent)]
    Db(#[from] DbError),
}

impl IntoResponse for QueryError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Prove(ProveError::Parse(_) | ProveError::StatementCount(_)) => {
                StatusCode::BAD_REQUEST
            }
            Self::Prove(ProveError::Snapshot(DbError::NotFound(_))) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

/// The body of `POST /query`.
#[derive(Debug, Deserialize)]
pub struct Query {
    /// The SQL to prove.
    sql: String,
}

/// One queried table's commitment, as included in a query response.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueriedTable {
    /// The commitment to every row, standard-binary-encoded and base64-wrapped.
    pub commitment: String,
    /// How many rows the table held when the commitment was taken.
    pub num_rows: usize,
}

/// The body of a successful `POST /query` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResult {
    /// The query's result rows, each keyed by column name.
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    /// The proof, standard-binary-encoded and base64-wrapped.
    pub proof: String,
    /// The commitments the proof was proved against, keyed by table reference.
    pub tables: HashMap<String, QueriedTable>,
}

/// Proves `sql` against the current database, returning the rows, the proof, and the
/// commitments it was proved against.
///
/// # Errors
/// Fails if `sql` is not exactly one valid statement, references a table that does not exist,
/// or the proof itself cannot be constructed.
pub async fn query(
    State(state): State<AppState>,
    Json(body): Json<Query>,
) -> Result<Json<QueryResult>, QueryError> {
    let table_refs = prove::table_refs(&body.sql)?;
    let (result, fields, commitments) = {
        let db = state.db.lock();
        let (result, fields) = prove(&db, &body.sql, &state.setup[..])?;
        let commitments = db.commitments(&table_refs)?;
        (result, fields, commitments)
    };

    let coerced = prove::coerce_scalars(result.result.clone(), &fields)?;
    let batch = RecordBatch::try_from(coerced)?;
    let mut writer = arrow::json::ArrayWriter::new(Vec::new());
    writer.write(&batch)?;
    writer.finish()?;
    let rows: Vec<serde_json::Map<String, serde_json::Value>> =
        serde_json::from_slice(&writer.into_inner())
            .expect("arrow's own array writer always produces a JSON array of objects");

    let proof_bytes =
        proof_of_sql::base::try_standard_binary_serialization(&result).map_err(DbError::Encode)?;
    let proof = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(proof_bytes)
    };

    let tables = commitments
        .iter()
        .map(|(table_ref, commitment)| {
            Ok((
                table_ref.to_string(),
                QueriedTable {
                    commitment: encode_commitment(commitment)?,
                    num_rows: commitment.num_rows(),
                },
            ))
        })
        .collect::<Result<HashMap<_, _>, DbError>>()?;

    Ok(Json(QueryResult {
        rows,
        proof,
        tables,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::super::router;
    use super::super::tests::{corrupt_commitment, test_state};

    async fn create_and_populate(state: &super::AppState) {
        router(state.clone())
            .oneshot(
                Request::post("/tables")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"table":"db.items","columns":[{"name":"id","type":"BIGINT"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        router(state.clone())
            .oneshot(
                Request::post("/tables/db.items/rows")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rows":[{"id":1}]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_query_can_be_proved() {
        let (_dir, state) = test_state();
        create_and_populate(&state).await;

        let response = router(state)
            .oneshot(
                Request::post("/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sql":"SELECT id FROM db.items"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn querying_an_unknown_table_is_not_found() {
        let (_dir, state) = test_state();

        let response = router(state)
            .oneshot(
                Request::post("/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sql":"SELECT id FROM db.missing"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_sql_is_a_bad_request() {
        let (_dir, state) = test_state();

        let response = router(state)
            .oneshot(
                Request::post("/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sql":"not valid sql"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_corrupt_commitment_is_an_internal_error() {
        let (dir, state) = test_state();
        create_and_populate(&state).await;
        corrupt_commitment(&dir, "db.items");

        let response = router(state)
            .oneshot(
                Request::post("/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"sql":"SELECT id FROM db.items"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
