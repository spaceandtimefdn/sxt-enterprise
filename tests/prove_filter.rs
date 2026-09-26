//! Proves a multi-row filter query through `Db`.

extern crate alloc;

use alloc::sync::Arc;

use arrow::array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use sxt_enterprise::db::Db;
use sxt_enterprise::prove::prove;
use sxt_enterprise::setup::prover;

/// The ceremony's smallest published file, 98 KB, holding enough powers for four rows.
const CEREMONY_URL: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau";

#[test]
fn we_can_prove_a_filter_query() {
    let setup = prover::from_ptau_url(CEREMONY_URL, 4).unwrap();
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("label", DataType::Utf8, false),
    ]));

    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path().to_path_buf()).unwrap();
    let table_ref = proof_of_sql::base::database::TableRef::new("db", "items");
    db.create_table(table_ref.clone(), &schema, &setup[..])
        .unwrap();
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef,
            Arc::new(StringArray::from(vec!["one", "two", "three"])) as ArrayRef,
        ],
    )
    .unwrap();
    db.insert(&table_ref, &batch, &setup[..]).unwrap();

    let (proof, _fields) =
        prove(&db, "SELECT label FROM db.items WHERE id = 2", &setup[..]).unwrap();

    assert_eq!(proof.result.num_rows(), 1);
}
