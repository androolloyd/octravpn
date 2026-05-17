#pragma once

#include <cstdint>
#include <vector>

#include "../core/types.hpp"
#include "../core/hash.hpp"
#include "../crypto/ristretto255.hpp"
#include "decrypt.hpp"

namespace pvac {

inline std::vector<std::vector<Fp>> compute_layer_coeffs(
    const PubKey& pk, const Cipher& ct
) {
    size_t S = ct.slots;
    size_t nL = ct.L.size();
    std::vector<std::vector<Fp>> A(nL, std::vector<Fp>(S, Fp{0,0}));

    for (const auto& e : ct.E) {
        Fp gp = pk.powg_B[e.idx];
        int sg = sgn_val(e.ch);
        for (size_t j = 0; j < S; j++) {
            Fp term = fp_mul(e.w[j], gp);
            A[e.layer_id][j] = sg > 0 ?
                fp_add(A[e.layer_id][j], term) :
                fp_sub(A[e.layer_id][j], term);
        }
    }
    return A;
}

inline Scalar derive_rho(const SecKey& sk, const Layer& L, size_t j) {
    Sha256 h;
    h.init();
    h.update(Dom::PRF_RHO, strlen(Dom::PRF_RHO));
    for (int k = 0; k < 4; k++) sha256_acc_u64(h, sk.prf_k[k]);
    sha256_acc_u64(h, L.seed.nonce.lo);
    sha256_acc_u64(h, L.seed.nonce.hi);
    sha256_acc_u64(h, (uint64_t)j);
    uint8_t rho_bytes[32];
    h.finish(rho_bytes);
    return sc_reduce256(rho_bytes);
}

inline Fp challenge_to_fp(const uint8_t hash[32]) {
    uint64_t lo = 0, hi = 0;
    for (int i = 0; i < 8; i++) lo |= ((uint64_t)hash[i]) << (i*8);
    for (int i = 0; i < 8; i++) hi |= ((uint64_t)hash[8+i]) << (i*8);
    hi &= (1ULL << 62) - 1;
    return Fp{lo, hi};
}

inline std::vector<size_t> base_layer_indices(const Cipher& ct) {
    std::vector<size_t> bases;
    for (size_t lid = 0; lid < ct.L.size(); lid++)
        if (ct.L[lid].rule == RRule::BASE) bases.push_back(lid);
    return bases;
}

}
