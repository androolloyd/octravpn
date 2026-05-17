#pragma once

#include <cstdint>
#include <vector>
#include <cassert>

#include "../crypto/bulletproofs/r1cs.hpp"
#include "../crypto/bulletproofs/gadgets.hpp"
#include "verify_zero.hpp"

namespace pvac {

struct ZeroProof {
    bp::R1CSProof proof;

    bool is_bound = false;
};

namespace detail {

struct CircuitWiring {

    struct SlotVar {
        bp::Variable x_var;
        Scalar x_val;
        bp::FpLimbs limbs;
    };
    std::vector<std::vector<SlotVar>> layer_vars;
};

struct AmountBinding {
    uint64_t amount = 0;
    Scalar blinding = sc_zero();
};

inline CircuitWiring build_circuit(
    bp::R1CSProver& prover,
    const Cipher& ct,
    const std::vector<std::vector<Fp>>& A,
    const std::vector<size_t>& bases,

    const std::vector<std::vector<Fp>>* rinv_ptr,
    const SecKey* sk_ptr,

    const AmountBinding* amount_bind = nullptr
) {
    size_t nL = ct.L.size();
    size_t S = ct.slots;
    size_t nB = bases.size();

    CircuitWiring w;
    w.layer_vars.resize(nL);
    for (size_t lid = 0; lid < nL; lid++)
        w.layer_vars[lid].resize(S);

    auto get_rinv = [&](size_t lid, size_t j) -> Fp {
        if (rinv_ptr) return (*rinv_ptr)[lid][j];
        return Fp{0, 0};
    };

    for (size_t bi = 0; bi < nB; bi++) {
        size_t lid = bases[bi];
        for (size_t j = 0; j < S; j++) {
            Fp rinv_fp = get_rinv(lid, j);

            Scalar signed_val = rinv_ptr ? sc_from_fp_signed(rinv_fp) : sc_zero();
            Scalar rho_j = (rinv_ptr && sk_ptr) ? derive_rho(*sk_ptr, ct.L[lid], j) : sc_zero();

            bp::Variable v_signed = prover.commit(signed_val, rho_j);

            auto bound = bp::bind_pc_value(prover, v_signed, rinv_fp);

            w.layer_vars[lid][j] = {bound.x_var, bound.x_val, bound.limbs};
        }
    }

    for (size_t lid = 0; lid < nL; lid++) {
        if (ct.L[lid].rule != RRule::PROD) continue;
        uint32_t pa = ct.L[lid].pa;
        uint32_t pb = ct.L[lid].pb;

        for (size_t j = 0; j < S; j++) {

            auto& va = w.layer_vars[pa][j];
            auto& vb = w.layer_vars[pb][j];
            auto result = bp::fp_mul_gadget(prover, va.x_var, va.x_val,
                                                     vb.x_var, vb.x_val);

            auto limbs = bp::fp127_decompose(prover, result.var, result.val);
            w.layer_vars[lid][j] = {result.var, result.val, limbs};
        }
    }

    bp::Variable amount_var;
    Scalar amount_scalar = sc_zero();
    if (amount_bind) {
        amount_scalar = bp::sc_from_u64(amount_bind->amount);
        Scalar blind = amount_bind->blinding;
        amount_var = prover.commit(amount_scalar, blind);
    }

    for (size_t j = 0; j < S; j++) {
        Fp c0_fp = ct.c0.empty() ? Fp{0, 0} : ct.c0[j];
        Scalar c0_scalar = Scalar{{c0_fp.lo, c0_fp.hi, 0, 0}};

        bp::LinearCombination sum_lc;
        if (c0_fp.lo != 0 || c0_fp.hi != 0)
            sum_lc += bp::LinearCombination(bp::Variable::one(), c0_scalar);

        if (amount_bind) {

            sum_lc -= bp::LinearCombination(amount_var);
        }

        Scalar total = amount_bind
            ? sc_sub(c0_scalar, amount_scalar)
            : c0_scalar;

        for (size_t lid = 0; lid < nL; lid++) {
            Fp a_coeff = A[lid][j];
            if (a_coeff.lo == 0 && a_coeff.hi == 0) continue;

            auto folded = bp::fp_mul_const_var_folded(a_coeff, w.layer_vars[lid][j].limbs);
            sum_lc += folded.lc;
            total = sc_add(total, folded.val);
        }

        Scalar p_sc = bp::sc_mersenne_p();
        Scalar k_val = sc_mul(total, sc_inv(p_sc));

        auto [k_var, k_r, k_o] = prover.allocate(k_val, bp::sc_from_u64(1));

        auto [kl, kr, k_out] = prover.multiply(
            bp::LinearCombination(k_var),
            bp::LinearCombination(bp::Variable::one(), p_sc)
        );

        bp::LinearCombination final_lc(k_out);
        final_lc -= sum_lc;
        prover.constrain(final_lc);

        bp::range_check(prover, k_var, k_val, 73);
    }

    return w;
}

}

inline ZeroProof make_zero_proof(
    const PubKey& pk, const SecKey& sk, const Cipher& ct
) {
    size_t nL = ct.L.size();
    size_t S = ct.slots;

    std::vector<std::vector<Fp>> cache(nL);
    std::vector<uint8_t> st(nL, 0);
    for (size_t lid = 0; lid < nL; lid++)
        layer_R_cached(pk, sk, ct, (uint32_t)lid, st, cache);

    std::vector<std::vector<Fp>> rinv(nL);
    for (size_t lid = 0; lid < nL; lid++) {
        rinv[lid].resize(S);
        for (size_t j = 0; j < S; j++)
            rinv[lid][j] = fp_inv(cache[lid][j]);
    }

    auto A = compute_layer_coeffs(pk, ct);
    auto bases = base_layer_indices(ct);
    size_t nB = bases.size();

    bp::R1CSProver prover;
    auto wiring = detail::build_circuit(prover, ct, A, bases, &rinv, &sk);

    bp::Transcript transcript("pvac.verify_zero.circuit");
    transcript.append_u64("nL", nL);
    transcript.append_u64("S", S);
    transcript.append_u64("nB", nB);

    ZeroProof result;
    result.proof = prover.prove(transcript);
    result.is_bound = false;
    return result;
}

inline bool verify_zero(
    const PubKey& pk, const Cipher& ct,
    const ZeroProof& proof
) {
    if (!is_cipher_compatible_with_pubkey(pk, ct)) return false;
    size_t nL = ct.L.size();
    size_t S = ct.slots;

    auto bases = base_layer_indices(ct);
    size_t nB = bases.size();

    if (proof.proof.V.size() != nB * S) return false;

    for (size_t bi = 0; bi < nB; bi++) {
        size_t lid = bases[bi];
        if (ct.L[lid].PC.size() != S) return false;
        for (size_t j = 0; j < S; j++) {
            if (proof.proof.V[bi * S + j] != ct.L[lid].PC[j])
                return false;
        }
    }

    auto A = compute_layer_coeffs(pk, ct);
    bp::R1CSProver dummy;
    detail::build_circuit(dummy, ct, A, bases, nullptr, nullptr);

    bp::ConstraintSystem cs;
    cs.num_gates = dummy.num_gates();
    cs.num_committed = dummy.num_committed();
    cs.constraints = dummy.get_constraints();

    bp::Transcript transcript("pvac.verify_zero.circuit");
    transcript.append_u64("nL", nL);
    transcript.append_u64("S", S);
    transcript.append_u64("nB", nB);

    return bp::r1cs_verify(transcript, cs, proof.proof);
}

inline ZeroProof make_zero_proof_bound(
    const PubKey& pk, const SecKey& sk, const Cipher& ct,
    uint64_t amount, const Scalar& amount_blinding
) {
    size_t nL = ct.L.size();
    size_t S = ct.slots;

    std::vector<std::vector<Fp>> cache(nL);
    std::vector<uint8_t> st(nL, 0);
    for (size_t lid = 0; lid < nL; lid++)
        layer_R_cached(pk, sk, ct, (uint32_t)lid, st, cache);

    std::vector<std::vector<Fp>> rinv(nL);
    for (size_t lid = 0; lid < nL; lid++) {
        rinv[lid].resize(S);
        for (size_t j = 0; j < S; j++)
            rinv[lid][j] = fp_inv(cache[lid][j]);
    }

    auto A = compute_layer_coeffs(pk, ct);
    auto bases = base_layer_indices(ct);
    size_t nB = bases.size();

    detail::AmountBinding bind;
    bind.amount = amount;
    bind.blinding = amount_blinding;

    bp::R1CSProver prover;
    auto wiring = detail::build_circuit(prover, ct, A, bases, &rinv, &sk, &bind);

    bp::Transcript transcript("pvac.verify_zero.circuit");
    transcript.append_u64("nL", nL);
    transcript.append_u64("S", S);
    transcript.append_u64("nB", nB);

    ZeroProof result;
    result.proof = prover.prove(transcript);
    result.is_bound = true;
    return result;
}

inline bool verify_zero_bound(
    const PubKey& pk, const Cipher& ct,
    const ZeroProof& proof,
    const RistrettoPoint& amount_commitment
) {
    if (!is_cipher_compatible_with_pubkey(pk, ct)) return false;
    size_t nL = ct.L.size();
    size_t S = ct.slots;

    auto bases = base_layer_indices(ct);
    size_t nB = bases.size();

    if (proof.proof.V.size() != nB * S + 1) return false;

    for (size_t bi = 0; bi < nB; bi++) {
        size_t lid = bases[bi];
        if (ct.L[lid].PC.size() != S) return false;
        for (size_t j = 0; j < S; j++) {
            if (proof.proof.V[bi * S + j] != ct.L[lid].PC[j])
                return false;
        }
    }

    if (proof.proof.V[nB * S] != amount_commitment) return false;

    auto A = compute_layer_coeffs(pk, ct);
    detail::AmountBinding dummy_bind;
    bp::R1CSProver dummy;
    detail::build_circuit(dummy, ct, A, bases, nullptr, nullptr, &dummy_bind);

    bp::ConstraintSystem cs;
    cs.num_gates = dummy.num_gates();
    cs.num_committed = dummy.num_committed();
    cs.constraints = dummy.get_constraints();

    bp::Transcript transcript("pvac.verify_zero.circuit");
    transcript.append_u64("nL", nL);
    transcript.append_u64("S", S);
    transcript.append_u64("nB", nB);

    return bp::r1cs_verify(transcript, cs, proof.proof);
}

}