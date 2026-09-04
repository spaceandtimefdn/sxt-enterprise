//! Proves and verifies a query against a `Db` that has been written to and reopened from disk,
//! exercising the whole storage stack: `Db`, `prove`, and `verify`.

extern crate alloc;

use alloc::sync::Arc;

use arrow::array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use proof_of_sql::base::commitment::QueryCommitments;
use proof_of_sql::base::database::TableRef;
use sxt_enterprise::db::Db;
use sxt_enterprise::prove::prove;
use sxt_enterprise::setup::prover;
use sxt_enterprise::verify::verify;

/// The ceremony's smallest published file, 98 KB, holding enough powers for four rows.
const CEREMONY_URL: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau";

#[test]
fn we_can_prove_and_verify_a_query_after_reopening_the_database() {
    let setup = prover::from_ptau_url(CEREMONY_URL, 4).unwrap();
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("label", DataType::Utf8, false),
    ]));
    let table_ref = TableRef::new("db", "items");

    let dir = tempfile::tempdir().unwrap();
    {
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        db.create_table(table_ref.clone(), &schema, &setup[..])
            .unwrap();
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef,
                Arc::new(StringArray::from(vec!["one", "two", "three"])) as ArrayRef,
            ],
        )
        .unwrap();
        db.insert(&table_ref, &batch, &setup[..]).unwrap();
    }

    // Reopen from disk: nothing above is still in memory.
    let db = Db::open(dir.path().to_path_buf()).unwrap();
    let sql = "SELECT label FROM db.items WHERE id = 2";
    let proof = prove(&db, sql, &setup[..]).unwrap();

    let commitments: QueryCommitments<_> = db
        .commitments(core::slice::from_ref(&table_ref))
        .unwrap()
        .into_iter()
        .collect();
    let verified = verify(sql, &commitments, proof).unwrap();

    assert_eq!(verified.num_rows(), 1);
}
