//! Proves and verifies a query end to end, exercising the whole `HyperKZG` stack.

use datafusion::config::ConfigOptions;
use proof_of_sql::base::database::owned_table_utility::{bigint, owned_table, varchar};
use proof_of_sql::base::database::{OwnedTableTestAccessor, TableRef};
use proof_of_sql::proof_primitive::hyperkzg::HyperKZGCommitmentEvaluationProof;
use proof_of_sql::sql::proof::VerifiableQueryResult;
use proof_of_sql_planner::sql_to_proof_plans;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sxt_enterprise::setup::{prover, verifier};

/// The ceremony's smallest published file, 98 KB, holding enough powers for four rows.
const CEREMONY_URL: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau";

#[test]
fn we_can_prove_and_verify_a_filter_query() {
    let setup = prover::from_ptau_url(CEREMONY_URL, 4).unwrap();

    let accessor = OwnedTableTestAccessor::<HyperKZGCommitmentEvaluationProof>::new_from_table(
        TableRef::new("db", "items"),
        owned_table([
            bigint("id", [1, 2, 3]),
            varchar("label", ["one", "two", "three"]),
        ]),
        0,
        &setup[..],
    );

    let sql = "SELECT label FROM db.items WHERE id = 2";
    let statements = Parser::parse_sql(&GenericDialect {}, sql).unwrap();
    let plan = &sql_to_proof_plans(&statements, &accessor, &ConfigOptions::default()).unwrap()[0];

    let proof = VerifiableQueryResult::<HyperKZGCommitmentEvaluationProof>::new(
        plan,
        &accessor,
        &&setup[..],
        &[],
    )
    .unwrap();

    let verified = proof
        .verify(plan, &accessor, &&verifier::setup(), &[])
        .unwrap();

    assert_eq!(verified.table, owned_table([varchar("label", ["two"])]));
}
