//! Loading the powers of tau the prover commits against.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use ark_serialize::{CanonicalSerialize, Validate};
use halo2curves::bn256::{G1Affine, G2Affine};
use nova_snark::provider::hyperkzg::CommitmentKey;
use nova_snark::provider::read_ptau;
use proof_of_sql::proof_primitive::hyperkzg::{
    HyperKZGEngine, HyperKZGPublicSetupOwned,
    deserialize_flat_compressed_hyperkzg_public_setup_from_slice,
    nova_commitment_key_to_hyperkzg_public_setup,
};

/// Bytes per ark-serialized compressed bn254 G1 point.
const POINT_SIZE: usize = 32;

/// Failure to load powers of tau.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// The setup file could not be read.
    #[error("setup file unreadable")]
    Read(#[from] std::io::Error),
    /// The setup holds fewer powers than were asked for.
    #[error("setup holds {available} powers, not {wanted}")]
    TooSmall {
        /// Powers the setup actually holds.
        available: usize,
        /// Powers the caller asked for.
        wanted: usize,
    },
    /// The setup's contents are not compressed bn254 points.
    #[error(transparent)]
    Deserialize(#[from] ark_serialize::SerializationError),
    /// The stream is not a valid `.ptau`, or holds fewer powers than asked for.
    #[error("invalid ptau: {0}")]
    Ptau(String),
    /// The ceremony file could not be fetched.
    #[error("ptau download failed")]
    Download(#[from] ureq::Error),
}

/// Takes the first `points` powers of tau from the compressed setup at `path`.
///
/// # Errors
/// Fails if the file cannot be read, holds fewer than `points` powers, or is not compressed
/// bn254 points.
pub fn from_file(path: &Path, points: usize) -> Result<HyperKZGPublicSetupOwned, SetupError> {
    from_compressed(&fs::read(path)?, points)
}

/// Downloads the `.ptau` at `url` and takes its first `points` powers of tau.
///
/// # Errors
/// Fails if the download fails, or the body is not a `.ptau` holding `points` powers.
pub fn from_ptau_url(url: &str, points: usize) -> Result<HyperKZGPublicSetupOwned, SetupError> {
    // Published files spend 576 bytes per power and hold under twice the powers asked for,
    // and 1 MiB covers the header.
    let limit = points as u64 * 1152 + (1 << 20);
    let ptau = ureq::get(url)
        .call()?
        .into_body()
        .into_with_config()
        .limit(limit)
        .read_to_vec()?;
    let powers = read_ptau::<G1Affine, G2Affine>(&mut Cursor::new(ptau), points, 0)
        .map_err(|error| SetupError::Ptau(error.to_string()))?
        .0;
    Ok(nova_commitment_key_to_hyperkzg_public_setup(
        &CommitmentKey::<HyperKZGEngine>::new(powers, G1Affine::generator(), G2Affine::generator()),
    ))
}

/// Flat-compresses `setup`'s powers, in the format [`from_file`] reads back.
///
/// # Panics
/// Never: writing to an in-memory `Vec` cannot fail.
#[must_use]
pub fn to_compressed(setup: &HyperKZGPublicSetupOwned) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(setup.len() * POINT_SIZE);
    for point in setup {
        // A `G1Affine` always serializes to exactly `POINT_SIZE` bytes.
        point
            .serialize_compressed(&mut bytes)
            .expect("an in-memory Vec never fails to write");
    }
    bytes
}

/// Deserializes the first `points` powers from a flat compressed setup.
fn from_compressed(bytes: &[u8], points: usize) -> Result<HyperKZGPublicSetupOwned, SetupError> {
    let wanted = points * POINT_SIZE;
    let powers = bytes.get(..wanted).ok_or(SetupError::TooSmall {
        available: bytes.len() / POINT_SIZE,
        wanted: points,
    })?;
    Ok(deserialize_flat_compressed_hyperkzg_public_setup_from_slice(powers, Validate::Yes)?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::TcpListener;

    use halo2curves::bn256::{G1Affine, G2Affine};
    use nova_snark::provider::write_ptau;

    use super::{SetupError, from_file, from_ptau_url, to_compressed};

    /// An in-memory `.ptau` of `power`, holding the `2^(power + 1) - 1` powers a real one does.
    fn ceremony(power: u32) -> Vec<u8> {
        let powers = vec![G1Affine::generator(); (1 << (power + 1)) - 1];
        let mut buffer = Cursor::new(Vec::new());
        write_ptau(&mut buffer, powers, vec![G2Affine::generator(); 2], power).unwrap();
        buffer.into_inner()
    }

    /// Serves `body` to one request and returns the URL it is served at.
    fn serve(body: Vec<u8>) -> String {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/setup.ptau", server.server_addr());
        std::thread::spawn(move || {
            let request = server.recv().unwrap();
            request
                .respond(tiny_http::Response::from_data(body))
                .unwrap();
        });
        url
    }

    /// A URL nothing is listening on.
    fn dead_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/setup.ptau", listener.local_addr().unwrap());
        drop(listener);
        url
    }

    /// A flat compressed setup of `points` powers, as a cached setup file holds them.
    fn compressed(points: usize) -> Vec<u8> {
        to_compressed(&from_ptau_url(&serve(ceremony(3)), points).unwrap())
    }

    #[test]
    fn a_file_setup_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.bin");
        std::fs::write(&path, compressed(8)).unwrap();

        assert_eq!(from_file(&path, 4).unwrap().len(), 4);
    }

    #[test]
    fn asking_a_file_for_too_many_powers_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.bin");
        std::fs::write(&path, compressed(4)).unwrap();
        let error = from_file(&path, 8).unwrap_err();

        assert_eq!(error.to_string(), "setup holds 4 powers, not 8");
    }

    #[test]
    fn a_file_ending_mid_point_is_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.bin");
        std::fs::write(&path, &compressed(2)[..33]).unwrap();
        let error = from_file(&path, 2).unwrap_err();

        assert_eq!(error.to_string(), "setup holds 1 powers, not 2");
    }

    #[test]
    fn a_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = from_file(&dir.path().join("absent.bin"), 1).unwrap_err();

        assert!(matches!(error, SetupError::Read(_)), "{error}");
    }

    #[test]
    fn garbage_points_are_a_deserialize_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.bin");
        std::fs::write(&path, [0xff_u8; 32]).unwrap();
        let error = from_file(&path, 1).unwrap_err();

        assert!(matches!(error, SetupError::Deserialize(_)), "{error}");
    }

    #[test]
    fn we_can_download_a_ptau() {
        assert_eq!(from_ptau_url(&serve(ceremony(2)), 7).unwrap().len(), 7);
    }

    #[test]
    fn asking_a_ptau_for_too_many_powers_is_an_error() {
        let error = from_ptau_url(&serve(ceremony(2)), 8).unwrap_err();

        assert!(matches!(error, SetupError::Ptau(_)), "{error}");
    }

    #[test]
    fn a_body_that_is_not_a_ptau_is_an_error() {
        let error = from_ptau_url(&serve(b"not a ptau".to_vec()), 1).unwrap_err();

        assert!(matches!(error, SetupError::Ptau(_)), "{error}");
    }

    #[test]
    fn a_body_beyond_the_limit_is_a_download_error() {
        let error = from_ptau_url(&serve(vec![0; 2 << 20]), 1).unwrap_err();

        assert!(matches!(error, SetupError::Download(_)), "{error}");
    }

    #[test]
    fn an_unreachable_url_is_a_download_error() {
        let error = from_ptau_url(&dead_url(), 1).unwrap_err();

        assert!(matches!(error, SetupError::Download(_)), "{error}");
    }
}
