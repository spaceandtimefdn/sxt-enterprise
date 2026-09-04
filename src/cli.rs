//! The `sxt-enterprise` command-line interface: serve, verify, and setup.

use core::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use proof_of_sql::base::commitment::QueryCommitments;
use proof_of_sql::base::database::TableRef;
use proof_of_sql::proof_primitive::hyperkzg::{
    HyperKZGCommitment, HyperKZGCommitmentEvaluationProof, HyperKZGPublicSetupOwned,
};
use proof_of_sql::sql::proof::VerifiableQueryResult;

use crate::api::{self, AppState, QueryResult};
use crate::db::{Db, DbError};
use crate::setup::prover::{self, SetupError};
use crate::verify::{self, VerifyError};

/// `sxt-enterprise`: a tiny deployable verifiable SQL service.
#[derive(Debug, Parser)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// A `sxt-enterprise` subcommand.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serves the HTTP API.
    Serve {
        /// The directory tables and the cached setup live under; defaults to
        /// `~/.sxt-enterprise`.
        #[arg(long)]
        data: Option<PathBuf>,
        /// The address to listen on.
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: SocketAddr,
        /// How many rows of proving capacity to provide.
        #[arg(long, default_value_t = 1024)]
        rows: usize,
    },
    /// Verifies a query response against pinned or self-reported commitments.
    Verify {
        /// The SQL the response claims to answer.
        #[arg(long)]
        sql: String,
        /// The `POST /query` response to verify, as saved to a file.
        #[arg(long)]
        response: PathBuf,
        /// A database directory to read pinned commitments from; defaults to
        /// `~/.sxt-enterprise`, falling back to trusting the response's own commitments if that
        /// directory doesn't exist.
        #[arg(long)]
        commitments: Option<PathBuf>,
    },
    /// Downloads or truncates powers of tau to an output file.
    Setup {
        /// How many rows of proving capacity to provide.
        #[arg(long)]
        rows: usize,
        /// Where to write the setup.
        #[arg(long, default_value = "setup.bin")]
        out: PathBuf,
    },
}

/// Failure to run a `sxt-enterprise` command.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A file could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The powers of tau could not be loaded.
    #[error(transparent)]
    Setup(#[from] SetupError),
    /// The database could not be opened.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The response file is not valid JSON in the expected shape.
    #[error(transparent)]
    Response(#[from] serde_json::Error),
    /// A base64 field in the response could not be decoded.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    /// A standard-binary-encoded field in the response could not be decoded.
    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),
    /// A table reference in the response could not be parsed.
    #[error(transparent)]
    TableName(#[from] proof_of_sql::base::database::ParseError),
    /// The proof did not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// The verified table could not be pretty-printed.
    #[error(transparent)]
    Arrow(#[from] arrow::error::ArrowError),
}

/// Runs `cli`.
///
/// # Errors
/// Fails if the requested command itself fails; see [`CliError`].
pub async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Serve { data, listen, rows } => {
            serve(data.unwrap_or_else(default_data_dir), listen, rows).await
        }
        Command::Verify {
            sql,
            response,
            commitments,
        } => verify_command(&sql, &response, commitments.as_deref()),
        Command::Setup { rows, out } => setup_command(rows, &out),
    }
}

/// The default data directory, `~/.sxt-enterprise`, used when `--data`/`--commitments` is
/// omitted.
fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map_or_else(PathBuf::new, PathBuf::from)
        .join(".sxt-enterprise")
}

/// The smallest power-of-two proving capacity that covers `rows`.
fn capacity_for(rows: usize) -> usize {
    rows.max(1).next_power_of_two()
}

/// The ceremony file whose powers cover `capacity`.
fn ptau_url_for(capacity: usize) -> String {
    format!(
        "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_{:02}.ptau",
        capacity.ilog2()
    )
}

/// Resolves `rows` of proving capacity from `data_dir/setup.bin`, downloading and caching a
/// ceremony file if the cache is missing or too small.
fn resolve_setup(data_dir: &Path, rows: usize) -> Result<HyperKZGPublicSetupOwned, CliError> {
    let capacity = capacity_for(rows);
    let cache = data_dir.join("setup.bin");
    if cache.exists() {
        match prover::from_file(&cache, capacity) {
            Ok(setup) => return Ok(setup),
            Err(SetupError::TooSmall { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let setup = prover::from_ptau_url(&ptau_url_for(capacity), capacity)?;
    std::fs::write(&cache, prover::to_compressed(&setup))?;
    Ok(setup)
}

/// Serves the HTTP API, resolving `rows` of proving capacity under `data` and listening on
/// `listen` until the process is killed.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn serve(data: PathBuf, listen: SocketAddr, rows: usize) -> Result<(), CliError> {
    std::fs::create_dir_all(&data)?;
    let setup = resolve_setup(&data, rows)?;
    let state = AppState::new(Db::open(data)?, setup);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}

/// Verifies `sql` against the response saved at `response_path`.
fn verify_command(
    sql: &str,
    response_path: &Path,
    commitments_dir: Option<&Path>,
) -> Result<(), CliError> {
    let response: QueryResult = serde_json::from_slice(&std::fs::read(response_path)?)?;

    let default_dir = default_data_dir();
    let commitments_dir = commitments_dir.unwrap_or(&default_dir);
    let commitments: QueryCommitments<HyperKZGCommitment> = if commitments_dir.exists() {
        response
            .tables
            .keys()
            .map(|table_ref| pinned_commitment(commitments_dir, table_ref))
            .collect::<Result<_, CliError>>()?
    } else {
        eprintln!(
            "warning: no --commitments given; trusting the commitments in the response itself, \
             which proves nothing about who computed them"
        );
        response
            .tables
            .iter()
            .map(|(table_ref, table)| {
                Ok((table_ref.parse()?, decode_commitment(&table.commitment)?))
            })
            .collect::<Result<_, CliError>>()?
    };

    let proof_bytes = decode_base64(&response.proof)?;
    let (proof, _): (
        VerifiableQueryResult<HyperKZGCommitmentEvaluationProof>,
        usize,
    ) = proof_of_sql::base::try_standard_binary_deserialization(&proof_bytes)?;

    let verified = verify::verify(sql, &commitments, proof)?;
    println!(
        "{}",
        arrow::util::pretty::pretty_format_batches(core::slice::from_ref(&verified))?
    );
    Ok(())
}

/// Reads `table_ref`'s pinned commitment from `dir`, a database's own data directory.
fn pinned_commitment(
    dir: &Path,
    table_ref: &str,
) -> Result<
    (
        TableRef,
        proof_of_sql::base::commitment::TableCommitment<HyperKZGCommitment>,
    ),
    CliError,
> {
    let bytes = std::fs::read(dir.join(table_ref).join("table.commit"))?;
    let (commitment, _) = proof_of_sql::base::try_standard_binary_deserialization(&bytes)?;
    Ok((table_ref.parse()?, commitment))
}

/// Base64-decodes and standard-binary-deserializes a commitment.
fn decode_commitment(
    encoded: &str,
) -> Result<proof_of_sql::base::commitment::TableCommitment<HyperKZGCommitment>, CliError> {
    let bytes = decode_base64(encoded)?;
    let (commitment, _) = proof_of_sql::base::try_standard_binary_deserialization(&bytes)?;
    Ok(commitment)
}

/// Base64-decodes `encoded`.
fn decode_base64(encoded: &str) -> Result<Vec<u8>, CliError> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
}

/// Downloads `rows` of proving capacity and writes it to `out`.
fn setup_command(rows: usize, out: &Path) -> Result<(), CliError> {
    let capacity = capacity_for(rows);
    let setup = prover::from_ptau_url(&ptau_url_for(capacity), capacity)?;
    std::fs::write(out, prover::to_compressed(&setup))?;
    println!("wrote {} powers to {}", setup.len(), out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use proof_of_sql::base::database::owned_table_utility::{bigint, owned_table};

    use super::{
        CliError, capacity_for, default_data_dir, ptau_url_for, resolve_setup, setup_command,
        verify_command,
    };
    use crate::api::{QueriedTable, QueryResult};
    use crate::db::Db;

    #[test]
    fn default_data_dir_lives_under_home() {
        assert!(default_data_dir().ends_with(".sxt-enterprise"));
    }

    #[test]
    fn capacity_rounds_up_to_a_power_of_two() {
        assert_eq!(capacity_for(0), 1);
        assert_eq!(capacity_for(1), 1);
        assert_eq!(capacity_for(5), 8);
        assert_eq!(capacity_for(8), 8);
    }

    #[test]
    fn the_ptau_url_names_the_requested_power() {
        assert!(ptau_url_for(4).ends_with("ppot_0080_02.ptau"));
        assert!(ptau_url_for(1024).ends_with("ppot_0080_10.ptau"));
    }

    /// A real proof and its commitments, over a trivial one-row table.
    fn any_response() -> (&'static str, QueryResult, tempfile::TempDir) {
        let setup = crate::setup::prover::from_ptau_url(
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau",
            2,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().to_path_buf()).unwrap();
        let table_ref = proof_of_sql::base::database::TableRef::new("db", "items");
        let schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("id", arrow::datatypes::DataType::Int64, false),
        ]));
        db.create_table(table_ref.clone(), &schema, &setup[..])
            .unwrap();
        let batch = arrow::array::RecordBatch::try_from(owned_table::<
            proof_of_sql::proof_primitive::hyperkzg::BNScalar,
        >([bigint("id", [1])]))
        .unwrap();
        db.insert(&table_ref, &batch, &setup[..]).unwrap();

        let sql = "SELECT id FROM db.items";
        let proof = crate::prove::prove(&db, sql, &setup[..]).unwrap();
        let commitments = db.commitments(core::slice::from_ref(&table_ref)).unwrap();
        let proof_bytes = proof_of_sql::base::try_standard_binary_serialization(&proof).unwrap();
        let proof_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(proof_bytes)
        };

        let tables = commitments
            .into_iter()
            .map(|(table_ref, commitment)| {
                let bytes =
                    proof_of_sql::base::try_standard_binary_serialization(&commitment).unwrap();
                let commitment_b64 = {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                };
                (
                    table_ref.to_string(),
                    QueriedTable {
                        commitment: commitment_b64,
                        num_rows: 1,
                    },
                )
            })
            .collect();

        (
            sql,
            QueryResult {
                rows: vec![],
                proof: proof_b64,
                tables,
            },
            dir,
        )
    }

    #[test]
    fn a_response_verifies_against_its_own_commitments() {
        let (sql, response, dir) = any_response();
        let response_path = dir.path().join("response.json");
        std::fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();

        verify_command(sql, &response_path, Some(&dir.path().join("absent"))).unwrap();
    }

    #[test]
    fn a_response_verifies_against_pinned_commitments() {
        let (sql, response, dir) = any_response();
        let response_path = dir.path().join("response.json");
        std::fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();

        verify_command(sql, &response_path, Some(dir.path())).unwrap();
    }

    #[test]
    fn an_unreadable_response_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = verify_command("SELECT 1", &dir.path().join("absent.json"), None).unwrap_err();

        assert!(matches!(error, CliError::Io(_)), "{error}");
    }

    #[test]
    fn a_non_json_response_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("response.json");
        std::fs::write(&path, b"not json").unwrap();

        let error = verify_command("SELECT 1", &path, None).unwrap_err();

        assert!(matches!(error, CliError::Response(_)), "{error}");
    }

    #[test]
    fn resolve_setup_downloads_then_reuses_the_cache() {
        let dir = tempfile::tempdir().unwrap();

        let downloaded = resolve_setup(dir.path(), 4).unwrap();
        assert_eq!(downloaded.len(), 4);
        assert!(dir.path().join("setup.bin").exists());

        let cached = resolve_setup(dir.path(), 4).unwrap();
        assert_eq!(cached.len(), 4);
    }

    #[test]
    fn resolve_setup_redownloads_a_too_small_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.bin"), []).unwrap();

        let resolved = resolve_setup(dir.path(), 4).unwrap();
        assert_eq!(resolved.len(), 4);
    }

    #[test]
    fn resolve_setup_rejects_a_corrupt_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.bin"), [0xff_u8; 128]).unwrap();

        let error = resolve_setup(dir.path(), 4).unwrap_err();

        assert!(matches!(error, CliError::Setup(_)), "{error}");
    }

    #[test]
    fn setup_command_writes_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("setup.bin");

        setup_command(4, &out).unwrap();

        assert!(out.exists());
    }

    #[tokio::test]
    async fn run_dispatches_setup() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("setup.bin");

        super::run(super::Cli {
            command: super::Command::Setup {
                rows: 4,
                out: out.clone(),
            },
        })
        .await
        .unwrap();

        assert!(out.exists());
    }

    #[tokio::test]
    async fn run_dispatches_verify() {
        let (sql, response, dir) = any_response();
        let response_path = dir.path().join("response.json");
        std::fs::write(&response_path, serde_json::to_vec(&response).unwrap()).unwrap();

        super::run(super::Cli {
            command: super::Command::Verify {
                sql: sql.to_owned(),
                response: response_path,
                commitments: Some(dir.path().join("absent")),
            },
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn run_dispatches_serve() {
        let dir = tempfile::tempdir().unwrap();

        let handle = tokio::spawn(super::run(super::Cli {
            command: super::Command::Serve {
                data: Some(dir.path().to_path_buf()),
                listen: "127.0.0.1:0".parse().unwrap(),
                rows: 4,
            },
        }));
        tokio::time::sleep(core::time::Duration::from_millis(200)).await;
        handle.abort();
    }
}
