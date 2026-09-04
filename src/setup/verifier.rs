//! The key proofs are checked against, which depends on no prover setup at all.

use halo2curves::bn256::{Fq, Fq2, G1Affine, G2Affine};
use nova_snark::provider::hyperkzg::{CommitmentKey, EvaluationEngine, VerifierKey};
use nova_snark::traits::evaluation::EvaluationEngineTrait;
use proof_of_sql::proof_primitive::hyperkzg::HyperKZGEngine;

/// `tau_h` from Perpetual Powers of Tau contribution 0080, the key's only input.
const TAU_H: G2Affine = G2Affine {
    x: Fq2::new(
        Fq::from_raw([
            0x2a74_74c0_708b_ef80,
            0xf762_edcf_ecfe_1c73,
            0x2340_a37d_fae9_005f,
            0x285b_1f14_edd7_e663,
        ]),
        Fq::from_raw([
            0x85ad_b083_e48c_197b,
            0x39c2_b413_1094_5472,
            0xda72_7c1d_ef86_0103,
            0x17cc_9307_7f56_f654,
        ]),
    ),
    y: Fq2::new(
        Fq::from_raw([
            0xc6db_5ddb_9bde_7fd0,
            0x0931_3450_580c_4c17,
            0x29ec_66e8_f530_f685,
            0x2bad_9a37_4aec_49d3,
        ]),
        Fq::from_raw([
            0xa630_d3c7_cdaa_6ed9,
            0xe32d_d53b_1584_4956,
            0x674f_5b2f_6fdb_69d9,
            0x219e_dfce_ee17_23de,
        ]),
    ),
};

/// Builds the key proofs are checked against, valid against prover setups of any size.
#[must_use]
pub fn setup() -> VerifierKey<HyperKZGEngine> {
    let key = CommitmentKey::new(vec![], G1Affine::generator(), TAU_H);
    EvaluationEngine::<HyperKZGEngine>::setup(&key).1
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use halo2curves::bn256::{G1Affine, G2Affine};
    use nova_snark::provider::read_ptau;

    use super::{TAU_H, setup};

    /// The ceremony's smallest published file, 98 KB, enough to carry `tau_h`.
    const CEREMONY_URL: &str =
        "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_02.ptau";

    #[test]
    fn we_can_build_the_verifier_key() {
        let key = setup();

        assert_eq!(format!("{key:?}"), format!("{:?}", setup()));
    }

    #[test]
    fn tau_h_matches_the_ceremony() {
        let ptau = ureq::get(CEREMONY_URL)
            .call()
            .unwrap()
            .into_body()
            .read_to_vec()
            .unwrap();
        let ceremony = read_ptau::<G1Affine, G2Affine>(&mut Cursor::new(ptau), 1, 2).unwrap();

        assert_eq!(ceremony.1[1], TAU_H);
    }

    #[test]
    fn tau_h_is_not_the_generator() {
        assert_ne!(TAU_H, G2Affine::generator());
    }
}
