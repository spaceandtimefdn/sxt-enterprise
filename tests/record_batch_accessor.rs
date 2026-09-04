//! Proves and verifies a multi-column query through `proof_of_sql`'s own
//! `DataAccessorImpl`/`TableDataAccessor`.

extern crate alloc;

use alloc::sync::Arc;

use arrow::array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use bumpalo::Bump;
use datafusion::config::ConfigOptions;
use proof_of_sql::base::commitment::{QueryCommitments, TableCommitment};
use proof_of_sql::base::database::{DataAccessorImpl, TableDataAccessor, TableRef};
use proof_of_sql::proof_primitive::hyperkzg::{
    HyperKZGCommitment, HyperKZGCommitmentEvaluationProof,
};
use proof_of_sql::sql::proof::VerifiableQueryResult;
use proof_of_sql_planner::sql_to_proof_plans;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sxt_enterprise::setup::{prover, verifier};

/// The ceremony's smallest published file, 98 KB, holding enough powers for four rows.
const CEREMONY_URL: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau";

#[test]
fn we_can_prove_and_verify_a_two_column_query() {
    let setup = prover::from_ptau_url(CEREMONY_URL, 4).unwrap();

    let batch = RecordBatch::try_from_iter([
        ("id", Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef),
        (
            "label",
            Arc::new(StringArray::from(vec!["one", "two", "three"])) as ArrayRef,
        ),
    ])
    .unwrap();
    let table_ref = TableRef::new("db", "items");

    let commitment = TableCommitment::try_from_record_batch(&batch, &&setup[..]).unwrap();
    let commitments: QueryCommitments<HyperKZGCommitment> =
        [(table_ref.clone(), commitment)].into_iter().collect();

    let alloc = Bump::new();
    let table_data = TableDataAccessor::try_from_record_batch(&batch, 0, &alloc).unwrap();
    let data_accessor = DataAccessorImpl::new([(table_ref, table_data)].into_iter().collect());

    let sql = "SELECT label FROM db.items WHERE id = 2";
    let statements = Parser::parse_sql(&GenericDialect {}, sql).unwrap();
    let plan =
        &sql_to_proof_plans(&statements, &commitments, &ConfigOptions::default()).unwrap()[0];

    let proof = VerifiableQueryResult::<HyperKZGCommitmentEvaluationProof>::new(
        plan,
        &data_accessor,
        &&setup[..],
        &[],
    )
    .unwrap();

    let verified = proof
        .verify(plan, &commitments, &&verifier::setup(), &[])
        .unwrap();

    assert_eq!(
        verified.table,
        proof_of_sql::base::database::owned_table_utility::owned_table([
            proof_of_sql::base::database::owned_table_utility::varchar("label", ["two"])
        ])
    );
}
