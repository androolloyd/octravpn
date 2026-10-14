// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// Ownership/exception boundary. Crypto and serialization are pinned upstream.
#include "pvac_serialize.hpp"
#include <chrono>
#include <cstdio>
#include <memory>

namespace {
thread_local int failure = 0;
thread_local char reason[256] = {};
template<class T, class F> T guarded(F work, T fallback) noexcept {
    failure = 0; reason[0] = 0;
    try { return work(); }
    catch (const std::bad_alloc&) { failure = 2; std::snprintf(reason, sizeof(reason), "pvac: allocation failed"); }
    catch (const std::exception& e) { failure = 1; std::snprintf(reason, sizeof(reason), "%s", e.what()); }
    catch (...) { failure = 2; std::snprintf(reason, sizeof(reason), "pvac: unknown C++ exception"); }
    return fallback;
}
template<class T> T& object(void* pointer) { return *static_cast<T*>(pointer); }
}

extern "C" {
int octra_pvac_error() { return failure; }
const char* octra_pvac_error_message() { return reason; }
int octra_pvac_keygen(const uint8_t* seed, void** public_key, void** secret_key) {
    *public_key = nullptr; *secret_key = nullptr;
    return guarded<int>([&] {
        auto pk = std::make_unique<pvac::PubKey>(); auto sk = std::make_unique<pvac::SecKey>();
        pvac::keygen_from_seed(pvac::Params{}, *pk, *sk, seed);
        *public_key = pk.release(); *secret_key = sk.release(); return 0;
    }, -1);
}
void octra_pvac_free(void* value, int kind) {
    if (kind == 1) delete static_cast<pvac::PubKey*>(value);
    else if (kind == 2) delete static_cast<pvac::SecKey*>(value);
    else if (kind == 3) delete static_cast<pvac::Cipher*>(value);
}
void* octra_pvac_decode(const uint8_t* input, size_t size, int kind, bool cap) {
    return guarded<void*>([&]() -> void* {
        if (kind == 1) return new pvac::PubKey(pvac_ser::deserialize_pubkey(input, size));
        if (kind == 2) return new pvac::SecKey(pvac_ser::deserialize_seckey(input, size));
        return new pvac::Cipher(pvac_ser::deserialize_cipher(input, size, true, cap));
    }, nullptr);
}
uint8_t* octra_pvac_encode(void* value, int kind, size_t* size) {
    *size = 0;
    return guarded<uint8_t*>([&] {
        std::vector<uint8_t> bytes;
        if (kind == 1) bytes = pvac_ser::serialize_pubkey(object<pvac::PubKey>(value));
        else if (kind == 2) bytes = pvac_ser::serialize_seckey(object<pvac::SecKey>(value));
        else bytes = pvac_ser::serialize_cipher(object<pvac::Cipher>(value));
        auto* result = static_cast<uint8_t*>(std::malloc(bytes.size()));
        if (!result) throw std::bad_alloc();
        std::memcpy(result, bytes.data(), bytes.size()); *size = bytes.size(); return result;
    }, nullptr);
}
void octra_pvac_free_bytes(uint8_t* value) { std::free(value); }
void* octra_pvac_encrypt(void* pk, void* sk, uint64_t amount, const uint8_t* seed, bool zero) {
    return guarded<void*>([&] {
        auto& public_key = object<pvac::PubKey>(pk); auto& secret_key = object<pvac::SecKey>(sk);
        return new pvac::Cipher(zero ? pvac::enc_zero_seeded(public_key, secret_key, seed)
            : pvac::enc_value_seeded(public_key, secret_key, amount, seed));
    }, nullptr);
}
int octra_pvac_decrypt(void* pk, void* sk, void* ct, int64_t* amount) {
    return guarded<int>([&] {
        auto value = pvac::dec_value(object<pvac::PubKey>(pk), object<pvac::SecKey>(sk), object<pvac::Cipher>(ct));
        if (!pvac::fp_to_i64(value, *amount)) throw std::runtime_error("pvac: decrypted field value is outside int64 range");
        return 0;
    }, -1);
}
void* octra_pvac_add(void* pk, void* left, void* right, bool subtract) {
    return guarded<void*>([&] {
        auto& public_key = object<pvac::PubKey>(pk); auto& a = object<pvac::Cipher>(left); auto& b = object<pvac::Cipher>(right);
        return new pvac::Cipher(subtract ? pvac::ct_sub(public_key, a, b) : pvac::ct_add(public_key, a, b));
    }, nullptr);
}
void* octra_pvac_scale(void* pk, void* ct, int64_t factor, bool math) {
    return guarded<void*>([&] {
        auto scalar = math ? pvac::detail::fp_from_i64(factor) : pvac::fp_from_u64(static_cast<uint64_t>(factor));
        return new pvac::Cipher(pvac::ct_scale(object<pvac::PubKey>(pk), object<pvac::Cipher>(ct), scalar));
    }, nullptr);
}
void* octra_pvac_add_const(void* pk, void* ct, uint64_t lo, uint64_t hi, bool math) {
    return guarded<void*>([&] {
        return new pvac::Cipher(pvac::ct_add_const(object<pvac::PubKey>(pk), object<pvac::Cipher>(ct), pvac::Fp{lo, hi}, math));
    }, nullptr);
}
int octra_pvac_commit(void* pk, void* ct, uint8_t* output) {
    return guarded<int>([&] {
        auto commitment = pvac::commit_ct(object<pvac::PubKey>(pk), object<pvac::Cipher>(ct));
        std::memcpy(output, commitment.data(), 32); return 0;
    }, -1);
}
int octra_pvac_pedersen(uint64_t amount, const uint8_t* blinding, uint8_t* output) {
    return guarded<int>([&] {
        auto value = pvac::pedersen_commit(pvac::bp::sc_from_u64(amount), pvac::sc_reduce256(blinding));
        std::memcpy(output, value.data(), 32); return 0;
    }, -1);
}
#ifdef OCTRA_PVAC_BENCHMARK
double octra_pvac_reference_add(void* pk, void* ct, size_t iterations) {
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        void* result = octra_pvac_add(pk, ct, ct, false);
        if (!result) return -1;
        octra_pvac_free(result, 3);
    }
    return std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - start).count();
}
#endif
}
