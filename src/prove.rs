//! Proving a single-statement SQL query against a database snapshot.

use bumpalo::Bump;
use datafusion_common::config::ConfigOptions;
use proof_of_sql::base::database::{
    ArrowArrayToColumnConversionError, ColumnField, ColumnType, DataAccessorImpl, OwnedColumn,
    OwnedTable, ParseError, SchemaAccessorImpl, TableDataAccessor, TableRef,
};
use proof_of_sql::base::scalar::Scalar;
use proof_of_sql::base::{IndexMap, PlaceholderError};
use proof_of_sql::proof_primitive::hyperkzg::{
    HyperKZGCommitmentEvaluationProof, HyperKZGPublicSetup,
};
use proof_of_sql::sql::proof::{ProofPlan, VerifiableQueryResult};
use proof_of_sql_planner::{PlannerError, get_table_refs_from_statement, sql_to_proof_plans};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::{Parser, ParserError};

use crate::db::{Db, DbError};

/// Failure to prove a SQL query.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    /// The SQL could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParserError),
    /// The SQL was not exactly one statement.
    #[error("exactly one SQL statement is required, got {0}")]
    StatementCount(usize),
    /// A referenced table's name could not be parsed.
    #[error(transparent)]
    TableName(#[from] ParseError),
    /// The referenced tables could not be snapshotted.
    #[error(transparent)]
    Snapshot(#[from] DbError),
    /// The SQL could not be planned against the referenced tables.
    #[error(transparent)]
    Plan(#[from] PlannerError),
    /// A table's batch could not be converted to prover-side columns.
    #[error(transparent)]
    Column(#[from] ArrowArrayToColumnConversionError),
    /// The proof could not be constructed.
    #[error(transparent)]
    Prove(#[from] PlaceholderError),
    /// An aggregate result (e.g. `SUM`) did not fit in its column's declared type.
    #[error("aggregate result overflowed its column type")]
    ScalarOverflow,
}

/// The tables `sql`'s single statement references.
///
/// # Errors
/// Fails if `sql` is not exactly one valid statement.
pub fn table_refs(sql: &str) -> Result<Vec<TableRef>, ProveError> {
    let statements = Parser::parse_sql(&GenericDialect {}, sql)?;
    let [statement] = &statements[..] else {
        return Err(ProveError::StatementCount(statements.len()));
    };
    Ok(get_table_refs_from_statement(statement)?
        .into_iter()
        .collect())
}

/// Proves `sql` against `db`'s current data; a caller wanting to verify the proof must fetch
/// the referenced tables' commitments itself, e.g. via [`Db::snapshot`].
///
/// Returns the proof alongside the query's declared result column fields, which a caller needs
/// to interpret aggregate (e.g. `SUM`, `GROUP BY`) result columns via [`coerce_scalars`]: those
/// come back as raw finite-field scalars rather than their real numeric type.
///
/// # Errors
/// Fails if `sql` is not exactly one valid statement, references a table `db` does not have,
/// or the proof itself cannot be constructed.
///
/// # Panics
/// Panics if a stored table's schema holds a column type unsupported by `proof_of_sql`, which
/// cannot happen since the same conversion already succeeded when its commitment was built.
pub fn prove(
    db: &Db,
    sql: &str,
    setup: HyperKZGPublicSetup<'_>,
) -> Result<
    (
        VerifiableQueryResult<HyperKZGCommitmentEvaluationProof>,
        Vec<ColumnField>,
    ),
    ProveError,
> {
    let statements = Parser::parse_sql(&GenericDialect {}, sql)?;
    let [statement] = &statements[..] else {
        return Err(ProveError::StatementCount(statements.len()));
    };

    let table_refs: Vec<TableRef> = get_table_refs_from_statement(statement)?
        .into_iter()
        .collect();
    let tables = db.data(&table_refs)?;

    let schema_accessor = SchemaAccessorImpl::new(
        tables
            .iter()
            .map(|(table_ref, table)| {
                let schema = table
                    .schema()
                    .fields()
                    .iter()
                    .map(|field| {
                        let column_type = ColumnType::try_from(field.data_type().clone())
                            .expect("a stored table's schema was already validated when its commitment was built");
                        (field.name().as_str().into(), column_type)
                    })
                    .collect();
                (table_ref.clone(), schema)
            })
            .collect(),
    );

    // One statement in always yields exactly one plan out; see sql_to_posql_plans.
    let plans = sql_to_proof_plans(&statements, &schema_accessor, &ConfigOptions::default())?;
    let plan = &plans[0];
    let fields = plan.get_column_result_fields();

    let alloc = Bump::new();
    let data_lookup = tables
        .iter()
        .map(|(table_ref, table)| {
            let data = TableDataAccessor::try_from_record_batch(table, 0, &alloc)?;
            Ok((table_ref.clone(), data))
        })
        .collect::<Result<IndexMap<_, _>, ProveError>>()?;
    let data_accessor = DataAccessorImpl::new(data_lookup);

    let result = VerifiableQueryResult::<HyperKZGCommitmentEvaluationProof>::new(
        plan,
        &data_accessor,
        &setup,
        &[],
    )?;
    Ok((result, fields))
}

/// Coerces `table`'s aggregate result columns to `fields`' declared types.
///
/// `SUM`/`GROUP BY` results come back from proving as raw finite-field scalars
/// (`OwnedColumn::Scalar`), since summation happens in-field to avoid silently overflowing the
/// column's real numeric type; this converts them back to that type, as declared by the query
/// plan's own result fields (see [`prove`]).
///
/// # Errors
/// Fails if an aggregate result does not fit in its column's declared type.
///
/// # Panics
/// Never: `table`'s column count and each column's length are unchanged by coercion.
pub fn coerce_scalars<S: Scalar>(
    table: OwnedTable<S>,
    fields: &[ColumnField],
) -> Result<OwnedTable<S>, ProveError> {
    let columns = table
        .into_inner()
        .into_iter()
        .zip(fields)
        .map(|((name, column), field)| {
            let column = match column {
                OwnedColumn::Scalar(values) => coerce_scalar_column(values, field.data_type())?,
                column => column,
            };
            Ok((name, column))
        })
        .collect::<Result<Vec<_>, ProveError>>()?;
    Ok(OwnedTable::try_from_iter(columns).expect("column count and lengths are unchanged"))
}

/// Coerces a single aggregate result column of raw scalars to `to_type`.
fn coerce_scalar_column<S: Scalar>(
    values: Vec<S>,
    to_type: ColumnType,
) -> Result<OwnedColumn<S>, ProveError> {
    fn convert<S: Scalar + TryInto<T>, T>(values: Vec<S>) -> Result<Vec<T>, ProveError> {
        values
            .into_iter()
            .map(|value| value.try_into().map_err(|_| ProveError::ScalarOverflow))
            .collect()
    }

    Ok(match to_type {
        ColumnType::Uint8 => OwnedColumn::Uint8(convert(values)?),
        ColumnType::TinyInt => OwnedColumn::TinyInt(convert(values)?),
        ColumnType::SmallInt => OwnedColumn::SmallInt(convert(values)?),
        ColumnType::Int => OwnedColumn::Int(convert(values)?),
        ColumnType::BigInt => OwnedColumn::BigInt(convert(values)?),
        ColumnType::Int128 => OwnedColumn::Int128(convert(values)?),
        ColumnType::Decimal75(precision, scale) => OwnedColumn::Decimal75(precision, scale, values),
        _ => OwnedColumn::Scalar(values),
    })
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use arrow::array::{ArrayRef, Int64Array, RecordBatch, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use proof_of_sql::base::database::TableRef;
    use proof_of_sql::proof_primitive::hyperkzg::HyperKZGPublicSetupOwned;

    use super::{ProveError, prove, table_refs};
    use crate::db::Db;

    /// Enough powers of tau for tests that insert a handful of rows.
    fn setup() -> HyperKZGPublicSetupOwned {
        crate::setup::prover::from_ptau_url(
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau",
            4,
        )
        .unwrap()
    }

    fn schema() -> arrow::datatypes::SchemaRef {
        alloc::sync::Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("label", DataType::Utf8, false),
        ]))
    }

    fn db_with_items() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();
        let batch = RecordBatch::try_new(
            schema(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef,
                Arc::new(StringArray::from(vec!["one", "two", "three"])) as ArrayRef,
            ],
        )
        .unwrap();
        db.insert(&table_ref, &batch, &setup()[..]).unwrap();
        (dir, db)
    }

    /// A table with exactly one row and one column.
    fn db_with_one_row() -> (tempfile::TempDir, Db, TableRef) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let schema =
            alloc::sync::Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        let table_ref = TableRef::new("db", "singleton");
        db.create_table(table_ref.clone(), &schema, &setup()[..])
            .unwrap();
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int64Array::from(vec![1]))])
            .unwrap();
        db.insert(&table_ref, &batch, &setup()[..]).unwrap();
        (dir, db, table_ref)
    }

    #[test]
    fn we_can_prove_a_query_over_a_single_row() {
        let (_dir, db, _table_ref) = db_with_one_row();

        let (proof, _fields) = prove(&db, "SELECT id FROM db.singleton", &setup()[..]).unwrap();

        assert_eq!(proof.result.num_rows(), 1);
    }

    #[test]
    fn an_unbound_placeholder_is_rejected() {
        let (_dir, db, _table_ref) = db_with_one_row();

        let error = prove(
            &db,
            "SELECT id FROM db.singleton WHERE id = $1",
            &setup()[..],
        )
        .map(|_| ())
        .unwrap_err();

        assert!(matches!(error, ProveError::Prove(_)));
    }

    #[test]
    fn an_empty_sql_string_is_rejected() {
        let (_dir, db) = db_with_items();

        let error = prove(&db, "", &setup()[..]).map(|_| ()).unwrap_err();

        assert!(matches!(error, ProveError::StatementCount(0)));
    }

    #[test]
    fn multiple_statements_are_rejected() {
        let (_dir, db) = db_with_items();

        let error = prove(
            &db,
            "SELECT id FROM db.items; SELECT id FROM db.items",
            &setup()[..],
        )
        .map(|_| ())
        .unwrap_err();

        assert!(matches!(error, ProveError::StatementCount(2)));
    }

    #[test]
    fn invalid_sql_is_rejected() {
        let (_dir, db) = db_with_items();

        let error = prove(&db, "not valid sql", &setup()[..])
            .map(|_| ())
            .unwrap_err();

        assert!(matches!(error, ProveError::Parse(_)));
    }

    #[test]
    fn table_refs_of_an_empty_sql_string_is_rejected() {
        let error = table_refs("").map(|_| ()).unwrap_err();

        assert!(matches!(error, ProveError::StatementCount(0)));
    }

    #[test]
    fn a_query_on_an_unknown_table_is_rejected() {
        let (_dir, db) = db_with_items();

        let error = prove(&db, "SELECT id FROM db.missing", &setup()[..])
            .map(|_| ())
            .unwrap_err();

        assert!(matches!(error, ProveError::Snapshot(_)));
    }
}
