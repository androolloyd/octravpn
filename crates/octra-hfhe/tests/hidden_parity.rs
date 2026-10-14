use octra_hfhe::{
    field::Fp,
    recrypt::{chosen, hidden, profile},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
mod common;
fn number(case: &Value, key: &str) -> usize {
    case[key].as_str().unwrap().parse().unwrap()
}
fn flags(values: &[bool]) -> Value {
    json!(values.iter().map(|v| u8::from(*v)).collect::<Vec<_>>())
}
#[test]
fn native_hidden_coefficients_and_chosen_statement_decisions() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/hidden.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-hidden-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let bound = hidden::Bound {
            terms: number(case, "terms"),
            alpha_bits: number(case, "alpha"),
            row_bits: number(case, "row"),
        };
        let count = number(case, "count");
        let hm = hidden::Material {
            row_tags: (0..count)
                .map(|i| {
                    std::array::from_fn(|j| u8::try_from((i * 31 + j * 7 + 11) & 255).unwrap())
                })
                .collect(),
            bound,
        };
        let hs = hidden::Statement {
            alpha: (0..count)
                .map(|i| Fp::from_words((i * 19 + 3) as u64, 0))
                .collect(),
            bound,
        };
        let bits = number(case, "flags");
        let hp = hidden::Profile {
            reusable: bits & 1 != 0,
            visible_output: bits & 2 != 0,
            statement_bound: bits & 4 != 0,
            transcript_bound: bits & 8 != 0,
            certificate: match number(case, "cert") {
                0 => hidden::Certificate::None,
                1 => hidden::Certificate::Native,
                n => hidden::Certificate::Unknown(u8::try_from(n).unwrap()),
            },
        };
        let plan = hidden::plan(bound);
        let hd = hidden::decide(hp);
        let ht = hidden::Transcript::new(&hm, &hs).unwrap();
        let mut actual = json!({"plan":[plan.sum_bits,usize::from(plan.needs_p_correction),usize::from(plan.needs_wide_correction),usize::from(plan.admitted)],"profile":flags(&[hd.admitted,hd.rejects_basis_oracle,hd.needs_native_certificate,hidden::public_reset_admitted(hp,plan)]),"hidden":[hex::encode(hm.digest()),hex::encode(hs.digest()),hex::encode(ht.aggregate_tag),u8::from(ht.verify(&hm,&hs))]});
        let material = chosen::Material::new(hm, number(case, "target"), number(case, "slots"));
        let mut material = match material {
            Ok(value) => value,
            Err(error) => {
                actual["error"] = json!(error.to_string());
                assert_eq!(actual, case["expected"], "case {index}");
                continue;
            }
        };
        let mut statement = chosen::Statement {
            coefficients: hs,
            target_terms: number(case, "target"),
            slots: number(case, "slots"),
            query: number(case, "query"),
        };
        let mut output = chosen::Output::new(&material, &statement).unwrap();
        let mut transcript = chosen::Transcript::new(&material, &statement, &output);
        let mut policy = chosen::Policy::reusable(64);
        let mut budget = chosen::Budget {
            target_bits: number(case, "bits"),
            ..chosen::Budget::default()
        };
        match number(case, "budget") {
            1 => budget.proof = profile::Kind::ShaCompat,
            2 => budget.max_trace_units = 0,
            3 => budget.max_output_tags = 0,
            4 => budget.max_proof_bytes = 0,
            5 => budget.proof = profile::Kind::None,
            _ => {}
        }
        match number(case, "mutation") {
            1 => policy.reusable = false,
            2 => policy.hidden_output = false,
            3 => policy.statement_bound = false,
            4 => policy.transcript_bound = false,
            5 => policy.material_bound = false,
            6 => policy.no_basis_oracle = false,
            7 => policy.native_backend = false,
            8 => policy.max_queries = 0,
            9 => policy.certificate = hidden::Certificate::None,
            10 => material.kind = chosen::MaterialKind::RawRows,
            11 => material.kind = chosen::MaterialKind::VisibleCoefficients,
            12 => material.reusable = false,
            13 => material.has_raw_rows = true,
            14 => material.visible_coefficients = true,
            15 => material.hides_rows = false,
            16 => material.no_basis_oracle = false,
            17 => material.native_backend = false,
            18 => material.coefficients.bound.terms += 1,
            19 => material.target_terms += 1,
            20 => material.slots += 1,
            21 => statement.coefficients.bound.alpha_bits += 1,
            22 => statement.coefficients.bound.row_bits += 1,
            23 => statement.coefficients.alpha.push(Fp::from_words(4, 0)),
            24 => statement.target_terms += 1,
            25 => statement.slots += 1,
            26 => statement.query = 64,
            27 => output.hidden_coefficients = false,
            28 => output.visible_beta = true,
            29 => output.material_digest[0] ^= 1,
            30 => output.statement_digest[0] ^= 1,
            31 => output.output_digest[0] ^= 1,
            32 => output.coefficient_tags.clear(),
            33 => output.coefficient_tags[0][0] ^= 1,
            34 => transcript.plan.sum_bits += 1,
            35 => transcript.plan.needs_p_correction = !transcript.plan.needs_p_correction,
            36 => transcript.plan.needs_wide_correction = !transcript.plan.needs_wide_correction,
            37 => transcript.plan.admitted = !transcript.plan.admitted,
            38 => transcript.material_digest[0] ^= 1,
            39 => transcript.statement_digest[0] ^= 1,
            40 => transcript.output_digest[0] ^= 1,
            41 => transcript.transcript_digest[0] ^= 1,
            42 => transcript.statement_bound = false,
            43 => transcript.material_bound = false,
            44 => transcript.hidden_output = false,
            45 => transcript.no_basis_oracle = false,
            46 => transcript.native_backend = false,
            _ => {}
        }
        let decision = chosen::decide(policy, &material, &statement, &output, &transcript);
        let reusable =
            chosen::decide_reusable(policy, &material, &statement, &output, &transcript, budget);
        actual["chosen"] = flags(&[
            decision.admitted,
            decision.policy,
            decision.material,
            decision.statement,
            decision.output,
            decision.transcript,
            decision.privacy,
            decision.rejects_raw,
            decision.rejects_visible,
            decision.rejects_unbound,
            decision.rejects_basis_oracle,
            decision.rejects_query_budget,
            decision.rejects_wide,
        ]);
        actual["reusable"] = flags(&[
            reusable.admitted,
            reusable.privacy,
            reusable.proof,
            reusable.compact,
            reusable.output,
            reusable.budget,
            reusable.rejects_sha_compat,
            reusable.rejects_noncompact,
            reusable.rejects_underbudget,
            reusable.rejects_output_wide,
            reusable.rejects_proof_wide,
        ]);
        actual["digests"] = json!([
            hex::encode(material.digest()),
            hex::encode(statement.digest()),
            hex::encode(output.digest()),
            hex::encode(transcript.digest())
        ]);
        assert_eq!(actual, case["expected"], "case {index}");
    }
}
#[test]
fn hidden_output_allocation_and_undefined_native_zero_slots_fail_closed() {
    let mut material = chosen::Material::default();
    let mut statement = chosen::Statement::default();
    material.target_terms = usize::MAX;
    material.slots = 1;
    statement.target_terms = usize::MAX;
    statement.slots = 1;
    assert_eq!(
        chosen::Output::new(&material, &statement)
            .err()
            .unwrap()
            .to_string(),
        "HFHE allocation unavailable"
    );
    material.slots = 2;
    statement.slots = 2;
    assert_eq!(
        chosen::Output::new(&material, &statement)
            .err()
            .unwrap()
            .to_string(),
        "pvac: native hidden output size rejected"
    );
    let material = chosen::Material::default();
    let statement = chosen::Statement::default();
    let output = chosen::Output {
        material_digest: material.digest(),
        statement_digest: statement.digest(),
        hidden_coefficients: true,
        visible_beta: false,
        ..chosen::Output::default()
    };
    assert!(!output.admitted(&material, &statement));
}
