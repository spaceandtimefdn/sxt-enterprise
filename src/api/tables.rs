//! `POST /tables`, `GET /tables`, and `GET /tables/{table}`.

use alloc::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use proof_of_sql::base::commitment::TableCommitment;
use proof_of_sql::base::database::TableRef;
use proof_of_sql::proof_primitive::hyperkzg::HyperKZGCommitment;
use serde::{Deserialize, Serialize};

use super::AppState;
use crate::column::{self, UnsupportedType};
use crate::db::DbError;

/// Failure to create or look up a table over the HTTP API.
#[derive(Debug, thiserror::Error)]
pub enum TableError {
    /// The table reference in the request path or body could not be parsed.
    #[error(transparent)]
    TableName(#[from] proof_of_sql::base::database::ParseError),
    /// A column's type name is not one this service supports.
    #[error(transparent)]
    Column(#[from] UnsupportedType),
    /// The table could not be created, read, or found.
    #[error(transparent)]
    Db(#[from] DbError),
}

impl IntoResponse for TableError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::TableName(_) | Self::Column(_) => StatusCode::BAD_REQUEST,
            Self::Db(DbError::AlreadyExists(_)) => StatusCode::CONFLICT,
            Self::Db(DbError::NotFound(_)) => StatusCode::NOT_FOUND,
            Self::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

/// A single column's name and SQL type name.
#[derive(Debug, Serialize, Deserialize)]
pub struct Column {
    /// The column's name.
    pub name: String,
    /// The column's SQL type name, e.g. `"BIGINT"`.
    #[serde(rename = "type")]
    pub data_type: String,
}

/// The body of `POST /tables`.
#[derive(Debug, Deserialize)]
pub struct CreateTable {
    /// The table's reference, e.g. `"sxt.people"`.
    table: String,
    /// The table's columns, in order.
    columns: Vec<Column>,
}

/// Creates a new, empty table.
///
/// # Errors
/// Fails if `table` or a column's type cannot be parsed, or a table already exists under it.
pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateTable>,
) -> Result<StatusCode, TableError> {
    let table_ref: TableRef = body.table.parse()?;
    let fields = body
        .columns
        .iter()
        .map(|column| {
            Ok(Field::new(
                &column.name,
                column::parse_column_type(&column.data_type)?,
                false,
            ))
        })
        .collect::<Result<Vec<_>, UnsupportedType>>()?;
    let schema = Arc::new(Schema::new(fields));

    state
        .db
        .lock()
        .create_table(table_ref, &schema, &state.setup[..])?;
    Ok(StatusCode::CREATED)
}

/// The body of `GET /tables`.
#[derive(Debug, Serialize)]
pub struct TableList {
    /// Every table's reference, as `"schema.table"`.
    tables: Vec<String>,
}

/// Lists every table this database holds.
///
/// # Errors
/// Fails if the database's directory cannot be read.
pub async fn list(State(state): State<AppState>) -> Result<Json<TableList>, TableError> {
    let mut tables: Vec<String> = state
        .db
        .lock()
        .tables()?
        .iter()
        .map(ToString::to_string)
        .collect();
    tables.sort();
    Ok(Json(TableList { tables }))
}

/// The body of `GET /tables/{table}`.
#[derive(Debug, Serialize)]
pub struct TableDescription {
    /// The table's columns, in order.
    columns: Vec<Column>,
    /// How many rows the table holds.
    num_rows: usize,
    /// The commitment to every row, standard-binary-encoded and base64-wrapped.
    commitment: String,
}

/// Describes one table's schema, row count, and commitment.
///
/// # Errors
/// Fails if `table` cannot be parsed or does not exist.
pub async fn show(
    State(state): State<AppState>,
    Path(table): Path<String>,
) -> Result<Json<TableDescription>, TableError> {
    let table_ref: TableRef = table.parse()?;
    let commitment = state
        .db
        .lock()
        .commitments(core::slice::from_ref(&table_ref))?
        .shift_remove(&table_ref)
        .expect("just read this exact table's commitment");

    let columns = commitment
        .column_commitments()
        .column_metadata()
        .iter()
        .map(|(ident, metadata)| {
            let data_type = DataType::from(metadata.column_type());
            Ok(Column {
                name: ident.value.clone(),
                data_type: column::column_type_name(&data_type)?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, UnsupportedType>>()?;

    let num_rows = commitment.num_rows();
    Ok(Json(TableDescription {
        columns,
        num_rows,
        commitment: encode_commitment(&commitment)?,
    }))
}

/// Base64-encodes a commitment in `proof_of_sql`'s standard binary format.
pub(super) fn encode_commitment(
    commitment: &TableCommitment<HyperKZGCommitment>,
) -> Result<String, DbError> {
    use base64::Engine;
    let bytes = proof_of_sql::base::try_standard_binary_serialization(commitment)
        .map_err(DbError::Encode)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::super::router;
    use super::super::tests::{corrupt_commitment, test_state};

    #[tokio::test]
    async fn a_table_can_be_created_and_described() {
        let (_dir, state) = test_state();
        let response = router(state.clone())
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
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = router(state)
            .oneshot(
                Request::get("/tables/db.items")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn creating_a_duplicate_table_is_a_conflict() {
        let (_dir, state) = test_state();
        let body =
            || Body::from(r#"{"table":"db.items","columns":[{"name":"id","type":"BIGINT"}]}"#);
        router(state.clone())
            .oneshot(
                Request::post("/tables")
                    .header("content-type", "application/json")
                    .body(body())
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::post("/tables")
                    .header("content-type", "application/json")
                    .body(body())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn an_unknown_column_type_is_rejected() {
        let (_dir, state) = test_state();
        let response = router(state)
            .oneshot(
                Request::post("/tables")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"table":"db.items","columns":[{"name":"id","type":"NOPE"}]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn describing_an_unknown_table_is_not_found() {
        let (_dir, state) = test_state();
        let response = router(state)
            .oneshot(
                Request::get("/tables/db.missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_corrupt_commitment_is_an_internal_error() {
        let (dir, state) = test_state();
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
        corrupt_commitment(&dir, "db.items");

        let response = router(state)
            .oneshot(
                Request::get("/tables/db.items")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn tables_lists_created_tables() {
        let (_dir, state) = test_state();
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

        let response = router(state)
            .oneshot(Request::get("/tables").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
