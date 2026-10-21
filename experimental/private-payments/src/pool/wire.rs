//! Native OG16 wire, with a fixed public-input count for this circuit version.
use super::{encode_field, Statement, INPUTS};
use anyhow::{ensure, Result};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};

fn field<F: PrimeField>(out: &mut Vec<u8>, value: F) {
    let raw = value.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat_n(0, 32 - raw.len()));
    out.extend(raw);
}

fn g1(out: &mut Vec<u8>, point: &G1Affine) -> Result<()> {
    ensure!(!point.is_zero(), "native verifier rejects infinity");
    field(out, point.x);
    field(out, point.y);
    Ok(())
}

fn g2(out: &mut Vec<u8>, point: &G2Affine) -> Result<()> {
    ensure!(!point.is_zero(), "native verifier rejects infinity");
    field(out, point.x.c0);
    field(out, point.x.c1);
    field(out, point.y.c0);
    field(out, point.y.c1);
    Ok(())
}

pub fn key(key: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    ensure!(
        key.gamma_abc_g1.len() == INPUTS + 1,
        "wrong pool circuit public-input count"
    );
    let mut out = b"OG16V1".to_vec();
    out.extend((INPUTS as u32).to_be_bytes());
    g1(&mut out, &key.alpha_g1)?;
    for p in [&key.beta_g2, &key.gamma_g2, &key.delta_g2] {
        g2(&mut out, p)?;
    }
    for p in &key.gamma_abc_g1 {
        g1(&mut out, p)?;
    }
    Ok(out)
}

pub fn proof(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    let mut out = b"OG16P1".to_vec();
    g1(&mut out, &proof.a)?;
    g2(&mut out, &proof.b)?;
    g1(&mut out, &proof.c)?;
    Ok(out)
}

pub fn inputs(statement: &Statement) -> Vec<u8> {
    statement
        .fields()
        .into_iter()
        .flat_map(encode_field)
        .collect()
}
