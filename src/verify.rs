//! Verifying a proved query against pinned commitments.

use arrow::array::RecordBatch;
use datafusion_common::config::ConfigOptions;
use proof_of_sql::base::commitment::QueryCommitments;
use proof_of_sql::base::database::{ParseError, TableRef};
use proof_of_sql::proof_primitive::hyperkzg::{
    HyperKZGCommitment, HyperKZGCommitmentEvaluationProof,
};
use proof_of_sql::sql::proof::{QueryError, VerifiableQueryResult};
use proof_of_sql_planner::{PlannerError, get_table_refs_from_statement, sql_to_proof_plans};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::{Parser, ParserError};

use crate::setup::verifier;

/// Failure to verify a proved query.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The SQL could not be parsed.
    #[error(transparent)]
    Parse(#[from] ParserError),
    /// The SQL was not exactly one statement.
    #[error("exactly one SQL statement is required, got {0}")]
    StatementCount(usize),
    /// A table referenced by the SQL could not be parsed.
    #[error(transparent)]
    TableName(#[from] ParseError),
    /// A table referenced by the SQL is not among the pinned commitments.
    #[error("table {0} is not among the pinned commitments")]
    UnknownTable(TableRef),
    /// The SQL could not be planned against the pinned commitments.
    #[error(transparent)]
    Plan(#[from] PlannerError),
    /// The proof did not verify against the pinned commitments.
    #[error(transparent)]
    Verify(#[from] QueryError),
    /// The verified result could not be converted to a `RecordBatch`.
    #[error(transparent)]
    Result(#[from] arrow::error::ArrowError),
}

/// Verifies `proof` proves `sql` against `commitments`, returning the verified result.
///
/// Unlike [`prove`](crate::prove::prove), this takes no database: `commitments` are supplied
/// by the caller, who is trusted to have pinned them independently of whatever server
/// produced `proof`.
///
/// # Errors
/// Fails if `sql` is not exactly one valid statement, or `proof` does not verify against
/// `commitments`.
pub fn verify(
    sql: &str,
    commitments: &QueryCommitments<HyperKZGCommitment>,
    proof: VerifiableQueryResult<HyperKZGCommitmentEvaluationProof>,
) -> Result<RecordBatch, VerifyError> {
    let statements = Parser::parse_sql(&GenericDialect {}, sql)?;
    let [statement] = &statements[..] else {
        return Err(VerifyError::StatementCount(statements.len()));
    };

    for table_ref in get_table_refs_from_statement(statement)? {
        if !commitments.contains_key(&table_ref) {
            return Err(VerifyError::UnknownTable(table_ref));
        }
    }

    // One statement in always yields exactly one plan out; see sql_to_posql_plans.
    let plans = sql_to_proof_plans(
        core::slice::from_ref(statement),
        commitments,
        &ConfigOptions::default(),
    )?;
    let plan = &plans[0];

    let verified = proof.verify(plan, commitments, &&verifier::setup(), &[])?;
    Ok(RecordBatch::try_from(verified.table)?)
}

#[cfg(test)]
mod tests {
    use datafusion_common::config::ConfigOptions;
    use proof_of_sql::base::commitment::{QueryCommitments, TableCommitment};
    use proof_of_sql::base::database::owned_table_utility::{bigint, owned_table};
    use proof_of_sql::base::database::{OwnedTableTestAccessor, TableRef};
    use proof_of_sql::proof_primitive::hyperkzg::{
        HyperKZGCommitment, HyperKZGCommitmentEvaluationProof,
    };
    use proof_of_sql::sql::proof::VerifiableQueryResult;
    use proof_of_sql_planner::sql_to_proof_plans;
    use sqlparser::dialect::GenericDialect;
    use sqlparser::parser::Parser;

    use super::{VerifyError, verify};

    /// A real proof over a trivial one row table, only used as a placeholder value in tests
    /// of `verify`'s own input validation.
    fn any_proof() -> (
        &'static str,
        QueryCommitments<HyperKZGCommitment>,
        VerifiableQueryResult<HyperKZGCommitmentEvaluationProof>,
    ) {
        let setup = crate::setup::prover::from_ptau_url(
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau",
            2,
        )
        .unwrap();
        let table_ref = TableRef::new("db", "items");
        let table =
            owned_table::<proof_of_sql::proof_primitive::hyperkzg::BNScalar>([bigint("id", [1])]);
        let accessor = OwnedTableTestAccessor::<HyperKZGCommitmentEvaluationProof>::new_from_table(
            table_ref.clone(),
            table.clone(),
            0,
            &setup[..],
        );
        let sql = "SELECT id FROM db.items";
        let statements = Parser::parse_sql(&GenericDialect {}, sql).unwrap();
        let plan =
            &sql_to_proof_plans(&statements, &accessor, &ConfigOptions::default()).unwrap()[0];
        let proof = VerifiableQueryResult::<HyperKZGCommitmentEvaluationProof>::new(
            plan,
            &accessor,
            &&setup[..],
            &[],
        )
        .unwrap();
        let commitment = TableCommitment::try_from_record_batch(
            &arrow::array::RecordBatch::try_from(table).unwrap(),
            &&setup[..],
        )
        .unwrap();
        let commitments = [(table_ref, commitment)].into_iter().collect();
        (sql, commitments, proof)
    }

    #[test]
    fn we_can_verify_a_real_proof() {
        let (sql, commitments, proof) = any_proof();

        let verified = verify(sql, &commitments, proof).unwrap();

        assert_eq!(verified.num_rows(), 1);
    }

    #[test]
    fn an_empty_sql_string_is_rejected() {
        let (_sql, commitments, proof) = any_proof();

        let error = verify("", &commitments, proof).unwrap_err();

        assert!(matches!(error, VerifyError::StatementCount(0)));
    }

    #[test]
    fn multiple_statements_are_rejected() {
        let (_sql, commitments, proof) = any_proof();

        let error = verify(
            "SELECT id FROM db.items; SELECT id FROM db.items",
            &commitments,
            proof,
        )
        .unwrap_err();

        assert!(matches!(error, VerifyError::StatementCount(2)));
    }

    #[test]
    fn invalid_sql_is_rejected() {
        let (_sql, commitments, proof) = any_proof();

        let error = verify("not valid sql", &commitments, proof).unwrap_err();

        assert!(matches!(error, VerifyError::Parse(_)));
    }

    #[test]
    fn a_query_on_an_unknown_table_is_rejected() {
        let (_sql, commitments, proof) = any_proof();

        let error = verify("SELECT id FROM db.missing", &commitments, proof).unwrap_err();

        assert!(matches!(error, VerifyError::UnknownTable(_)));
    }

    #[test]
    fn a_query_on_an_unknown_column_is_rejected() {
        let (_sql, commitments, proof) = any_proof();

        let error = verify("SELECT missing FROM db.items", &commitments, proof).unwrap_err();

        assert!(matches!(error, VerifyError::Plan(_)));
    }
}
