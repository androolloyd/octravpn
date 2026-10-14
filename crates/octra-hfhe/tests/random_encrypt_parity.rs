use octra_hfhe::{
    encrypt,
    field::Fp,
    keys::{keygen_from_seed, CircuitProfile, Params},
    recrypt::native,
};
use rand::{CryptoRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
// Compact deterministic public fixture stream, never production entropy.
struct Entropy {
    state: u64,
    word: u64,
    available: usize,
    consumed: usize,
    calls: usize,
}
impl Entropy {
    fn new(state: u64) -> Self {
        Self {
            state,
            word: 0,
            available: 0,
            consumed: 0,
            calls: 0,
        }
    }
}
impl RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap();
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.calls += 1;
        self.consumed += bytes.len();
        for byte in bytes {
            if self.available == 0 {
                self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                self.word = z ^ (z >> 31);
                self.available = 8;
            }
            *byte = self.word as u8;
            self.word >>= 8;
            self.available -= 1;
        }
        Ok(())
    }
}
impl CryptoRng for Entropy {}

#[test]
fn native_unseeded_cipher_bytes_and_entropy_draws() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/random_encrypt.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-random-encrypt-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 90);
    for (index, case) in cases.iter().enumerate() {
        let params = Params {
            basis: 126,
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 127,
            noise_entropy_bits: case["noise"].as_f64().unwrap(),
            ..Params::default()
        };
        let (mut public, secret) =
            keygen_from_seed(params, &std::array::from_fn(|i| i as u8)).unwrap();
        public.set_circuit_profile(
            &secret,
            if case["profile"] == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let values = (0..case["slots"].as_u64().unwrap())
            .map(|i| Fp::from_u64(case["value"].as_u64().unwrap() + i))
            .collect::<Vec<_>>();
        let mut entropy = Entropy::new(case["entropy_seed"].as_u64().unwrap());
        let depth = case["depth"].as_i64().unwrap() as i32;
        let result = match case["operation"].as_u64().unwrap() {
            0 => encrypt::synthesize_random(&public, &secret, &values, depth, &mut entropy),
            1 => encrypt::fields_random(&public, &secret, &values, depth, &mut entropy),
            2 => native::encrypt_random(&public, &secret, &values, &mut entropy),
            operation => native::encrypt_seeded(
                &public,
                &secret,
                &values,
                &std::array::from_fn(|i| 31 - i as u8),
                if operation == 3 {
                    native::SourceDomain::Native
                } else {
                    native::SourceDomain::Reusable
                },
            ),
        };
        let expected = &case["expected"];
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "error {index}");
        } else {
            assert_eq!(
                hex::encode(result.unwrap().to_bytes().unwrap()),
                expected["bytes"],
                "cipher bytes {index}"
            );
        }
        assert_eq!(
            entropy.consumed,
            expected["consumed"].as_u64().unwrap() as usize,
            "entropy bytes {index}"
        );
        assert_eq!(
            entropy.calls,
            expected["calls"].as_u64().unwrap() as usize,
            "entropy calls {index}"
        );
    }
}
