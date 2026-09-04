//! A collection of tables, one directory per table, stored as parquet batches plus a
//! commitment, keyed by table reference.

use alloc::sync::Arc;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use arrow::array::{RecordBatch, RecordBatchReader};
use arrow::datatypes::SchemaRef;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use proof_of_sql::base::arrow::record_batch_errors::{
    AppendRecordBatchTableCommitmentError, RecordBatchToColumnsError,
};
use proof_of_sql::base::commitment::TableCommitment;
use proof_of_sql::base::database::TableRef;
use proof_of_sql::base::{
    IndexMap, try_standard_binary_deserialization, try_standard_binary_serialization,
};
use proof_of_sql::proof_primitive::hyperkzg::{HyperKZGCommitment, HyperKZGPublicSetup};

/// Failure to create a table in, or insert into, a database.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A file could not be read or written.
    #[error("store file unusable")]
    Io(#[from] std::io::Error),
    /// A parquet file could not be read or written.
    #[error(transparent)]
    Parquet(#[from] parquet::errors::ParquetError),
    /// The batches read back from parquet could not be combined.
    #[error(transparent)]
    Arrow(#[from] arrow::error::ArrowError),
    /// A commitment could not be serialized.
    #[error(transparent)]
    Encode(#[from] bincode::error::EncodeError),
    /// A commitment could not be deserialized.
    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),
    /// A batch could not be converted to a commitment.
    #[error(transparent)]
    Commit(#[from] RecordBatchToColumnsError),
    /// A batch could not be appended to the commitment.
    #[error(transparent)]
    Append(#[from] AppendRecordBatchTableCommitmentError),
    /// A table already exists under this reference.
    #[error("table {0} already exists")]
    AlreadyExists(TableRef),
    /// No table exists under this reference.
    #[error("table {0} does not exist")]
    NotFound(TableRef),
    /// The table's directory holds no parquet files.
    #[error("table holds no parquet files")]
    Empty,
    /// An inserted batch's schema does not match the table's.
    #[error("insert schema does not match the table's")]
    SchemaMismatch,
}

/// A collection of tables, one directory per table, keyed by table reference.
///
/// Holds no table data or commitments in memory: every operation reads and writes disk
/// directly, so there is nothing to keep in sync with it.
#[derive(Debug)]
pub struct Db {
    /// The directory each table's own directory lives under.
    dir: PathBuf,
}

impl Db {
    /// Opens the database at `dir`, creating it if it does not exist.
    ///
    /// # Errors
    /// Fails if `dir` cannot be created.
    pub fn open(dir: PathBuf) -> Result<Self, DbError> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Creates a new, empty table under `table_ref`.
    ///
    /// # Errors
    /// Fails if a table already exists under `table_ref`, or its files cannot be written.
    pub fn create_table(
        &self,
        table_ref: TableRef,
        schema: &SchemaRef,
        setup: HyperKZGPublicSetup<'_>,
    ) -> Result<(), DbError> {
        let dir = self.table_dir(&table_ref);
        if dir.exists() {
            return Err(DbError::AlreadyExists(table_ref));
        }
        fs::create_dir_all(&dir)?;
        let empty = RecordBatch::new_empty(schema.clone());
        write_batch(&batch_path(&dir, 0), &empty)?;
        let commitment = TableCommitment::try_from_record_batch_with_offset(&empty, 0, &setup)?;
        write_commitment(&commit_path(&dir), &commitment)?;
        Ok(())
    }

    /// Appends `batch` to the table under `table_ref`.
    ///
    /// # Errors
    /// Fails if no table exists under `table_ref`, `batch`'s schema does not match it, or its
    /// files cannot be written.
    pub fn insert(
        &self,
        table_ref: &TableRef,
        batch: &RecordBatch,
        setup: HyperKZGPublicSetup<'_>,
    ) -> Result<(), DbError> {
        let dir = self.table_dir(table_ref);
        if !dir.exists() {
            return Err(DbError::NotFound(table_ref.clone()));
        }
        let paths = parquet_paths(&dir)?;
        let schema = read_schema(paths.first().ok_or(DbError::Empty)?)?;
        if batch.schema() != schema {
            return Err(DbError::SchemaMismatch);
        }

        let mut commitment = read_commitment(&commit_path(&dir))?;
        write_batch(&batch_path(&dir, paths.len()), batch)?;
        commitment.try_append_record_batch(batch, &setup)?;
        write_commitment(&commit_path(&dir), &commitment)?;
        Ok(())
    }

    /// Reads each of `table_refs`' data fresh from disk, without its commitment.
    ///
    /// # Errors
    /// Fails if any of `table_refs` does not exist, or its files cannot be read.
    pub fn data(
        &self,
        table_refs: &[TableRef],
    ) -> Result<IndexMap<TableRef, RecordBatch>, DbError> {
        table_refs
            .iter()
            .map(|table_ref| Ok((table_ref.clone(), self.table_data(table_ref)?)))
            .collect()
    }

    /// Reads `table_ref`'s schema, without its data or commitment.
    ///
    /// # Errors
    /// Fails if `table_ref` does not exist, or its files cannot be read.
    pub fn schema(&self, table_ref: &TableRef) -> Result<SchemaRef, DbError> {
        let dir = self.table_dir(table_ref);
        if !dir.exists() {
            return Err(DbError::NotFound(table_ref.clone()));
        }
        let paths = parquet_paths(&dir)?;
        read_schema(paths.first().ok_or(DbError::Empty)?)
    }

    /// Reads each of `table_refs`' commitments fresh from disk, without their data.
    ///
    /// # Errors
    /// Fails if any of `table_refs` does not exist, or its files cannot be read.
    pub fn commitments(
        &self,
        table_refs: &[TableRef],
    ) -> Result<IndexMap<TableRef, TableCommitment<HyperKZGCommitment>>, DbError> {
        table_refs
            .iter()
            .map(|table_ref| {
                let dir = self.table_dir(table_ref);
                if !dir.exists() {
                    return Err(DbError::NotFound(table_ref.clone()));
                }
                Ok((table_ref.clone(), read_commitment(&commit_path(&dir))?))
            })
            .collect()
    }

    /// Reads `table_ref`'s data fresh from disk, without its commitment.
    fn table_data(&self, table_ref: &TableRef) -> Result<RecordBatch, DbError> {
        let dir = self.table_dir(table_ref);
        if !dir.exists() {
            return Err(DbError::NotFound(table_ref.clone()));
        }
        let paths = parquet_paths(&dir)?;
        let schema = read_schema(paths.first().ok_or(DbError::Empty)?)?;
        let batches = paths
            .iter()
            .map(|path| read_batch(path))
            .collect::<Result<Vec<_>, DbError>>()?;
        Ok(arrow::compute::concat_batches(&schema, &batches)?)
    }

    /// Every table this database currently holds, in no particular order.
    ///
    /// # Errors
    /// Fails if the database's directory cannot be read.
    pub fn tables(&self) -> Result<Vec<TableRef>, DbError> {
        Ok(fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect())
    }

    /// The directory `table_ref`'s files live in.
    fn table_dir(&self, table_ref: &TableRef) -> PathBuf {
        self.dir.join(table_ref.to_string())
    }
}

/// Every parquet file in a table's directory, in file order.
fn parquet_paths(dir: &Path) -> Result<Vec<PathBuf>, DbError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    paths.sort();
    Ok(paths)
}

/// The path a batch numbered `index` is stored at.
fn batch_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("{index:06}.parquet"))
}

/// The path a table's commitment is stored at.
fn commit_path(dir: &Path) -> PathBuf {
    dir.join("table.commit")
}

/// Writes `batch` to `path` as a single parquet file.
fn write_batch(path: &Path, batch: &RecordBatch) -> Result<(), DbError> {
    let mut writer = ArrowWriter::try_new(File::create(path)?, batch.schema(), None)?;
    writer.write(batch)?;
    writer.close()?;
    Ok(())
}

/// Reads the parquet file at `path` back into a single `RecordBatch`.
fn read_batch(path: &Path) -> Result<RecordBatch, DbError> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
    let schema = reader.schema().clone();
    let batches = reader.collect::<Result<Vec<_>, _>>()?;
    Ok(arrow::compute::concat_batches(&schema, &batches)?)
}

/// The arrow schema `path`'s parquet file was written with.
fn read_schema(path: &Path) -> Result<SchemaRef, DbError> {
    Ok(Arc::clone(
        ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.schema(),
    ))
}

/// Writes `commitment` to `path` in `proof_of_sql`'s standard binary format.
fn write_commitment(
    path: &Path,
    commitment: &TableCommitment<HyperKZGCommitment>,
) -> Result<(), DbError> {
    Ok(fs::write(
        path,
        try_standard_binary_serialization(commitment)?,
    )?)
}

/// Reads a commitment previously written by [`write_commitment`].
fn read_commitment(path: &Path) -> Result<TableCommitment<HyperKZGCommitment>, DbError> {
    let (commitment, _) = try_standard_binary_deserialization(&fs::read(path)?)?;
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use arrow::array::{ArrayRef, Int64Array, RecordBatch};
    use proof_of_sql::base::commitment::TableCommitment;
    use proof_of_sql::base::database::TableRef;
    use proof_of_sql::proof_primitive::hyperkzg::{HyperKZGCommitment, HyperKZGPublicSetupOwned};

    use super::{
        Db, DbError, read_batch, read_commitment, read_schema, write_batch, write_commitment,
    };

    /// Enough powers of tau for tests that insert a handful of rows.
    fn setup() -> HyperKZGPublicSetupOwned {
        crate::setup::prover::from_ptau_url(
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau",
            4,
        )
        .unwrap()
    }

    fn schema() -> arrow::datatypes::SchemaRef {
        Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("id", arrow::datatypes::DataType::Int64, false),
        ]))
    }

    fn batch(ids: Vec<i64>) -> RecordBatch {
        RecordBatch::try_new(schema(), vec![Arc::new(Int64Array::from(ids)) as ArrayRef]).unwrap()
    }

    #[test]
    fn a_batch_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000000.parquet");
        write_batch(&path, &batch(vec![1, 2, 3])).unwrap();

        assert_eq!(read_batch(&path).unwrap(), batch(vec![1, 2, 3]));
    }

    #[test]
    fn the_schema_is_readable_without_the_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000000.parquet");
        write_batch(&path, &batch(vec![1, 2, 3])).unwrap();

        assert_eq!(read_schema(&path).unwrap(), batch(vec![1, 2, 3]).schema());
    }

    #[test]
    fn writing_to_a_missing_directory_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            write_batch(&dir.path().join("no/such/dir.parquet"), &batch(vec![1])).unwrap_err();

        assert!(matches!(error, DbError::Io(_)), "{error}");
    }

    #[test]
    fn reading_a_missing_batch_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_batch(&dir.path().join("absent.parquet")).unwrap_err();

        assert!(matches!(error, DbError::Io(_)), "{error}");
    }

    #[test]
    fn a_non_parquet_file_is_a_parquet_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not_parquet.parquet");
        std::fs::write(&path, b"not parquet").unwrap();
        let error = read_batch(&path).unwrap_err();

        assert!(matches!(error, DbError::Parquet(_)), "{error}");
    }

    #[test]
    fn a_commitment_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.commit");
        let commitment = TableCommitment::<HyperKZGCommitment>::default();
        write_commitment(&path, &commitment).unwrap();

        assert_eq!(read_commitment(&path).unwrap(), commitment);
    }

    #[test]
    fn writing_a_commitment_to_a_missing_directory_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let commitment = TableCommitment::<HyperKZGCommitment>::default();
        let error =
            write_commitment(&dir.path().join("no/such/dir.commit"), &commitment).unwrap_err();

        assert!(matches!(error, DbError::Io(_)), "{error}");
    }

    #[test]
    fn reading_a_missing_commitment_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_commitment(&dir.path().join("absent.commit")).unwrap_err();

        assert!(matches!(error, DbError::Io(_)), "{error}");
    }

    #[test]
    fn a_corrupt_commitment_is_a_decode_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.commit");
        std::fs::write(&path, [0xff_u8; 4]).unwrap();
        let error = read_commitment(&path).unwrap_err();

        assert!(matches!(error, DbError::Decode(_)), "{error}");
    }

    #[test]
    fn a_created_table_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();

        let data = db.data(core::slice::from_ref(&table_ref)).unwrap();
        let commitments = db.commitments(core::slice::from_ref(&table_ref)).unwrap();

        assert_eq!(data[&table_ref].num_rows(), 0);
        assert_eq!(commitments[&table_ref].num_rows(), 0);
    }

    #[test]
    fn a_created_table_can_be_inserted_into_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();
        db.insert(&table_ref, &batch(vec![1, 2, 3]), &setup()[..])
            .unwrap();

        let data = db.data(core::slice::from_ref(&table_ref)).unwrap();
        let commitments = db.commitments(core::slice::from_ref(&table_ref)).unwrap();

        assert_eq!(data[&table_ref].num_rows(), 3);
        assert_eq!(commitments[&table_ref].num_rows(), 3);
    }

    #[test]
    fn multiple_inserts_concatenate() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();
        db.insert(&table_ref, &batch(vec![1, 2]), &setup()[..])
            .unwrap();
        db.insert(&table_ref, &batch(vec![3]), &setup()[..])
            .unwrap();

        let data = db.data(core::slice::from_ref(&table_ref)).unwrap();
        let commitments = db.commitments(core::slice::from_ref(&table_ref)).unwrap();

        assert_eq!(data[&table_ref], batch(vec![1, 2, 3]));
        assert_eq!(commitments[&table_ref].num_rows(), 3);
    }

    #[test]
    fn a_table_schema_is_readable_via_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();

        assert_eq!(db.schema(&table_ref).unwrap(), schema());
    }

    #[test]
    fn creating_a_duplicate_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();

        let error = db
            .create_table(table_ref, &schema(), &setup()[..])
            .unwrap_err();

        assert!(matches!(error, DbError::AlreadyExists(_)));
    }

    #[test]
    fn inserting_into_an_unknown_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();

        let error = db
            .insert(
                &TableRef::new("db", "missing"),
                &batch(vec![1]),
                &setup()[..],
            )
            .unwrap_err();

        assert!(matches!(error, DbError::NotFound(_)));
    }

    #[test]
    fn inserting_a_mismatched_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        db.create_table(table_ref.clone(), &schema(), &setup()[..])
            .unwrap();
        let mismatched_schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("other", arrow::datatypes::DataType::Int64, false),
        ]));
        let mismatched = RecordBatch::try_new(
            mismatched_schema,
            vec![Arc::new(Int64Array::from(vec![1])) as ArrayRef],
        )
        .unwrap();

        let error = db
            .insert(&table_ref, &mismatched, &setup()[..])
            .unwrap_err();

        assert!(matches!(error, DbError::SchemaMismatch), "{error}");
    }

    #[test]
    fn reading_data_of_an_unknown_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();

        let error = db.data(&[TableRef::new("db", "missing")]).unwrap_err();

        assert!(matches!(error, DbError::NotFound(_)));
    }

    #[test]
    fn reading_the_schema_of_an_unknown_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();

        let error = db.schema(&TableRef::new("db", "missing")).unwrap_err();

        assert!(matches!(error, DbError::NotFound(_)));
    }

    #[test]
    fn reading_the_commitments_of_an_unknown_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();

        let error = db
            .commitments(&[TableRef::new("db", "missing")])
            .unwrap_err();

        assert!(matches!(error, DbError::NotFound(_)));
    }

    #[test]
    fn reading_data_of_a_directory_with_no_parquet_files_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        std::fs::create_dir_all(dir.path().join(table_ref.to_string())).unwrap();

        let error = db.data(core::slice::from_ref(&table_ref)).unwrap_err();

        assert!(matches!(error, DbError::Empty), "{error}");
    }

    #[test]
    fn reading_the_schema_of_a_directory_with_no_parquet_files_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = TableRef::new("db", "items");
        std::fs::create_dir_all(dir.path().join(table_ref.to_string())).unwrap();

        let error = db.schema(&table_ref).unwrap_err();

        assert!(matches!(error, DbError::Empty), "{error}");
    }

    #[test]
    fn reopening_finds_the_same_table() {
        let dir = tempfile::tempdir().unwrap();
        let table_ref = TableRef::new("db", "items");
        {
            let db = Db::open(dir.path().to_path_buf()).unwrap();
            db.create_table(table_ref.clone(), &schema(), &setup()[..])
                .unwrap();
            db.insert(&table_ref, &batch(vec![1, 2, 3]), &setup()[..])
                .unwrap();
        }

        let reopened = Db::open(dir.path().to_path_buf()).unwrap();
        let data = reopened.data(core::slice::from_ref(&table_ref)).unwrap();

        assert_eq!(data[&table_ref].num_rows(), 3);
    }
}
