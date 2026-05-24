/*
    PVAC sidecar — JSON-over-stdio daemon producing chain-compatible
    HFHE pubkey / ciphertext / zero-proof blobs for Octra's v2 substrate.

    This program is part of Octra Wallet (webcli) — vendored subset, GPL-2+.
    It is released under the GNU General Public License, version 2 or
    later, with the additional permission that compiling, linking,
    and/or using OpenSSL is allowed.

    See LICENSE for the full license text and LICENSE.NOTICE.md for the
    boundary statement between this GPL'd binary and the surrounding
    MIT/Apache Rust workspace.

    Copyright 2025-2026 Octra Labs (vendored PVAC)
    Copyright 2025-2026 OctraVPN contributors (sidecar wrapper)

    --

    Wire protocol (one request per stdin line, one response per stdout
    line; both UTF-8 JSON):

      keygen
        > {"op":"keygen","seed":"<32-byte hex>"}
        < {"pk":"hfhe_v1|<b64>","sk":"hfhe_v1|<b64>"}

      encrypt_zero
        > {"op":"encrypt_zero","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
           "seed":"<32-byte hex>"}
        < {"ct":"hfhe_v1|<b64>"}

      encrypt_const
        > {"op":"encrypt_const","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
           "value":"<u64 decimal>","seed":"<32-byte hex>"}
        < {"ct":"hfhe_v1|<b64>"}

      make_zero_proof
        > {"op":"make_zero_proof","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
           "ct":"hfhe_v1|...","amount":"<u64 decimal>",
           "blinding":"<base64 32 bytes>"}
        < {"proof":"zkzp_v2|<b64>"}

      add
        > {"op":"add","pk":"hfhe_v1|...","a":"hfhe_v1|...",
           "b":"hfhe_v1|..."}
        < {"ct":"hfhe_v1|<b64>"}

      receipt_shadow (Perf-4: batched HFHE-2 receipt-shadow emission)
        > {"op":"receipt_shadow","pk":"hfhe_v1|...","sk":"hfhe_v1|...",
           "bytes_used":"<u64 decimal>","net":"<u64 decimal>",
           "seed_bytes":"<32-byte hex>","seed_net":"<32-byte hex>",
           "blinding":"<base64 32 bytes>"}
        < {"enc_bytes_used":"hfhe_v1|<b64>",
           "enc_net":"hfhe_v1|<b64>",
           "zero_proof":"zkzp_v2|<b64>"}

        Single round-trip combining 2x encrypt_const + 1x
        make_zero_proof. Byte-for-byte identical to issuing those
        three ops serially with the same (pk, sk, value, seed) tuples
        and blinding. The win is in IPC framing (one syscall round-trip,
        one JSON parse, one JSON serialize) not the math itself.

      ping (no-op)
        > {"op":"ping"}
        < {"pong":true}

    Errors: {"error":"<short message>"}

    Everything is stateless — each request fully specifies its inputs.
    The sidecar never logs secret material to stdout; if PVAC_SIDECAR_DEBUG
    is set, only opaque op names + result lengths go to stderr.
*/

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "lib/json.hpp"
#include "lib/b64.hpp"

extern "C" {
#include "pvac/pvac_c_api.h"
}

using nlohmann::json;

namespace {

constexpr const char* HFHE_PREFIX = "hfhe_v1|";
constexpr const char* ZKZP_PREFIX = "zkzp_v2|";

bool debug_enabled() {
    static const bool v = std::getenv("PVAC_SIDECAR_DEBUG") != nullptr;
    return v;
}

void dbg(const std::string& msg) {
    if (debug_enabled())
        std::cerr << "[pvac-sidecar] " << msg << "\n";
}

// --- small helpers ------------------------------------------------------

std::vector<uint8_t> hex_decode(const std::string& s_in) {
    auto s = s_in;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
    if (s.size() % 2 != 0) throw std::runtime_error("hex length must be even");
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = nib(s[i * 2]);
        int lo = nib(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("invalid hex char");
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

void require_seed32(const std::vector<uint8_t>& s, const char* field) {
    if (s.size() != 32) {
        std::ostringstream os;
        os << field << " must be 32 bytes (got " << s.size() << ")";
        throw std::runtime_error(os.str());
    }
}

uint64_t parse_u64(const json& v, const char* field) {
    if (v.is_string()) {
        const std::string s = v.get<std::string>();
        if (s.empty()) {
            std::ostringstream os;
            os << field << " is empty";
            throw std::runtime_error(os.str());
        }
        // Reject negative values; std::stoull would silently accept them.
        for (char c : s) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                std::ostringstream os;
                os << field << " must be decimal u64";
                throw std::runtime_error(os.str());
            }
        }
        try {
            return std::stoull(s);
        } catch (...) {
            std::ostringstream os;
            os << field << " overflows u64";
            throw std::runtime_error(os.str());
        }
    }
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) {
        auto i = v.get<int64_t>();
        if (i < 0) {
            std::ostringstream os;
            os << field << " must be non-negative";
            throw std::runtime_error(os.str());
        }
        return static_cast<uint64_t>(i);
    }
    std::ostringstream os;
    os << field << " must be number or decimal string";
    throw std::runtime_error(os.str());
}

// Strip the "hfhe_v1|" prefix, base64-decode the rest. Mirrors the
// PvacBridge::decode_cipher pattern; tightened so we reject ill-formed
// inputs before they reach the C ABI.
std::vector<uint8_t> strip_prefix(const std::string& s, const char* prefix) {
    const size_t plen = std::strlen(prefix);
    if (s.size() < plen || std::memcmp(s.data(), prefix, plen) != 0) {
        std::ostringstream os;
        os << "expected prefix '" << prefix << "'";
        throw std::runtime_error(os.str());
    }
    return octra::base64_decode(s.substr(plen));
}

std::string with_prefix(const char* prefix, const std::vector<uint8_t>& bytes) {
    return std::string(prefix) + octra::base64_encode(bytes.data(), bytes.size());
}

// --- RAII wrappers around the opaque C handles --------------------------
//
// The PVAC C API allocates new pvac::PubKey / pvac::SecKey / pvac::Cipher
// / pvac::ZeroProof / pvac::Params instances on every call. Use scope
// guards so a thrown exception (bad-input branch in process_request) never
// leaks them.

template <typename Free>
struct Guard {
    void* h;
    Free  freer;
    Guard(void* h_, Free f) : h(h_), freer(f) {}
    ~Guard() { if (h) freer(h); }
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
};

#define PVAC_GUARD_PASTE2(a, b) a##b
#define PVAC_GUARD_PASTE(a, b)  PVAC_GUARD_PASTE2(a, b)
#define GUARD(handle, freer) \
    Guard<decltype(&freer)> PVAC_GUARD_PASTE(_g_, __LINE__)(handle, &freer)

// --- core helpers around the C API -------------------------------------

std::vector<uint8_t> serialize_pubkey(pvac_pubkey pk) {
    size_t len = 0;
    uint8_t* buf = pvac_serialize_pubkey(pk, &len);
    if (!buf || !len) throw std::runtime_error("serialize_pubkey failed");
    std::vector<uint8_t> out(buf, buf + len);
    pvac_free_bytes(buf);
    return out;
}

std::vector<uint8_t> serialize_seckey(pvac_seckey sk) {
    size_t len = 0;
    uint8_t* buf = pvac_serialize_seckey(sk, &len);
    if (!buf || !len) throw std::runtime_error("serialize_seckey failed");
    std::vector<uint8_t> out(buf, buf + len);
    pvac_free_bytes(buf);
    return out;
}

std::vector<uint8_t> serialize_cipher(pvac_cipher ct) {
    size_t len = 0;
    uint8_t* buf = pvac_serialize_cipher(ct, &len);
    if (!buf || !len) throw std::runtime_error("serialize_cipher failed");
    std::vector<uint8_t> out(buf, buf + len);
    pvac_free_bytes(buf);
    return out;
}

std::vector<uint8_t> serialize_zero_proof(pvac_zero_proof zp) {
    size_t len = 0;
    uint8_t* buf = pvac_serialize_zero_proof(zp, &len);
    if (!buf || !len) throw std::runtime_error("serialize_zero_proof failed");
    std::vector<uint8_t> out(buf, buf + len);
    pvac_free_bytes(buf);
    return out;
}

pvac_pubkey deser_pubkey(const std::string& hfhe_pk) {
    auto raw = strip_prefix(hfhe_pk, HFHE_PREFIX);
    pvac_pubkey pk = pvac_deserialize_pubkey(raw.data(), raw.size());
    if (!pk) throw std::runtime_error("pubkey deserialization failed");
    return pk;
}

pvac_seckey deser_seckey(const std::string& hfhe_sk) {
    auto raw = strip_prefix(hfhe_sk, HFHE_PREFIX);
    pvac_seckey sk = pvac_deserialize_seckey(raw.data(), raw.size());
    if (!sk) throw std::runtime_error("seckey deserialization failed");
    return sk;
}

pvac_cipher deser_cipher(const std::string& hfhe_ct) {
    auto raw = strip_prefix(hfhe_ct, HFHE_PREFIX);
    pvac_cipher ct = pvac_deserialize_cipher(raw.data(), raw.size());
    if (!ct) throw std::runtime_error("cipher deserialization failed");
    return ct;
}

// --- op handlers --------------------------------------------------------

json op_keygen(const json& req) {
    auto seed = hex_decode(req.at("seed").get<std::string>());
    require_seed32(seed, "seed");

    pvac_params prm = pvac_default_params();
    if (!prm) throw std::runtime_error("pvac_default_params failed");
    GUARD(prm, pvac_free_params);

    pvac_pubkey pk = nullptr;
    pvac_seckey sk = nullptr;
    pvac_keygen_from_seed(prm, seed.data(), &pk, &sk);
    if (!pk || !sk) throw std::runtime_error("pvac_keygen_from_seed failed");
    GUARD(pk, pvac_free_pubkey);
    GUARD(sk, pvac_free_seckey);

    auto pk_bytes = serialize_pubkey(pk);
    auto sk_bytes = serialize_seckey(sk);
    dbg("keygen: pk=" + std::to_string(pk_bytes.size()) +
        "B sk=" + std::to_string(sk_bytes.size()) + "B");

    return json{
        {"pk", with_prefix(HFHE_PREFIX, pk_bytes)},
        {"sk", with_prefix(HFHE_PREFIX, sk_bytes)},
    };
}

json op_encrypt_zero(const json& req) {
    auto seed = hex_decode(req.at("seed").get<std::string>());
    require_seed32(seed, "seed");

    pvac_pubkey pk = deser_pubkey(req.at("pk").get<std::string>());
    GUARD(pk, pvac_free_pubkey);

    pvac_seckey sk = deser_seckey(req.at("sk").get<std::string>());
    GUARD(sk, pvac_free_seckey);

    pvac_cipher ct = pvac_enc_zero_seeded(pk, sk, seed.data());
    if (!ct) throw std::runtime_error("pvac_enc_zero_seeded returned null");
    GUARD(ct, pvac_free_cipher);

    auto bytes = serialize_cipher(ct);
    dbg("encrypt_zero: " + std::to_string(bytes.size()) + "B");
    return json{{"ct", with_prefix(HFHE_PREFIX, bytes)}};
}

json op_encrypt_const(const json& req) {
    auto seed = hex_decode(req.at("seed").get<std::string>());
    require_seed32(seed, "seed");
    uint64_t value = parse_u64(req.at("value"), "value");

    pvac_pubkey pk = deser_pubkey(req.at("pk").get<std::string>());
    GUARD(pk, pvac_free_pubkey);

    pvac_seckey sk = deser_seckey(req.at("sk").get<std::string>());
    GUARD(sk, pvac_free_seckey);

    pvac_cipher ct = pvac_enc_value_seeded(pk, sk, value, seed.data());
    if (!ct) throw std::runtime_error("pvac_enc_value_seeded returned null");
    GUARD(ct, pvac_free_cipher);

    auto bytes = serialize_cipher(ct);
    dbg("encrypt_const(" + std::to_string(value) + "): " +
        std::to_string(bytes.size()) + "B");
    return json{{"ct", with_prefix(HFHE_PREFIX, bytes)}};
}

json op_make_zero_proof(const json& req) {
    uint64_t amount = parse_u64(req.at("amount"), "amount");
    auto blinding = octra::base64_decode(req.at("blinding").get<std::string>());
    if (blinding.size() != 32)
        throw std::runtime_error("blinding must be 32 bytes (base64)");

    pvac_pubkey pk = deser_pubkey(req.at("pk").get<std::string>());
    GUARD(pk, pvac_free_pubkey);

    pvac_seckey sk = deser_seckey(req.at("sk").get<std::string>());
    GUARD(sk, pvac_free_seckey);

    pvac_cipher ct = deser_cipher(req.at("ct").get<std::string>());
    GUARD(ct, pvac_free_cipher);

    pvac_zero_proof zp =
        pvac_make_zero_proof_bound(pk, sk, ct, amount, blinding.data());
    if (!zp) throw std::runtime_error("pvac_make_zero_proof_bound returned null");
    GUARD(zp, pvac_free_zero_proof);

    auto bytes = serialize_zero_proof(zp);
    dbg("make_zero_proof(amount=" + std::to_string(amount) + "): " +
        std::to_string(bytes.size()) + "B");
    return json{{"proof", with_prefix(ZKZP_PREFIX, bytes)}};
}

// Perf-4: batched receipt-shadow emission. Combines what used to be
// 2x encrypt_const + 1x make_zero_proof into one IPC round-trip. The
// internals run the *same* libpvac calls in the *same* order against
// the *same* inputs (caller-supplied per-field seeds and 32-byte
// blinding), so the output is byte-identical to the legacy serial
// path. The win is purely in IPC framing: one read, one write, one
// JSON parse, one JSON serialize.
//
// Backwards compatible with the existing encrypt_const + make_zero_proof
// ops — they're left in place for non-receipt callers (e.g. PVAC
// pubkey registration which only needs encrypt_zero / encrypt_const).
json op_receipt_shadow(const json& req) {
    uint64_t bytes_used = parse_u64(req.at("bytes_used"), "bytes_used");
    uint64_t net        = parse_u64(req.at("net"),        "net");

    auto seed_b = hex_decode(req.at("seed_bytes").get<std::string>());
    require_seed32(seed_b, "seed_bytes");
    auto seed_n = hex_decode(req.at("seed_net").get<std::string>());
    require_seed32(seed_n, "seed_net");

    auto blinding = octra::base64_decode(req.at("blinding").get<std::string>());
    if (blinding.size() != 32)
        throw std::runtime_error("blinding must be 32 bytes (base64)");

    pvac_pubkey pk = deser_pubkey(req.at("pk").get<std::string>());
    GUARD(pk, pvac_free_pubkey);

    pvac_seckey sk = deser_seckey(req.at("sk").get<std::string>());
    GUARD(sk, pvac_free_seckey);

    // Step 1: encrypt(bytes_used). The cipher we keep around is also
    // the one fed to make_zero_proof below — identical to what the
    // legacy three-call path used to do (signer used the bytes_used
    // ciphertext, not the net one, for the proof).
    pvac_cipher ct_b = pvac_enc_value_seeded(pk, sk, bytes_used, seed_b.data());
    if (!ct_b) throw std::runtime_error("pvac_enc_value_seeded(bytes_used) returned null");
    GUARD(ct_b, pvac_free_cipher);

    // Step 2: encrypt(net) under its own (per-field-distinct) seed.
    pvac_cipher ct_n = pvac_enc_value_seeded(pk, sk, net, seed_n.data());
    if (!ct_n) throw std::runtime_error("pvac_enc_value_seeded(net) returned null");
    GUARD(ct_n, pvac_free_cipher);

    // Step 3: zero-proof bound to (bytes_used, blinding) and the
    // *bytes_used* ciphertext. This must match the legacy three-call
    // wiring in `crates/octravpn-node/src/control/handlers/receipt.rs`
    // exactly: see the `make_zero_proof` call there — `amount` is
    // `event_bytes`, `ct` is `enc_b`. If you change either side, the
    // determinism test in `pvac.rs::tests::receipt_shadow_matches_legacy_serial_calls`
    // will trip.
    pvac_zero_proof zp =
        pvac_make_zero_proof_bound(pk, sk, ct_b, bytes_used, blinding.data());
    if (!zp) throw std::runtime_error("pvac_make_zero_proof_bound returned null");
    GUARD(zp, pvac_free_zero_proof);

    auto bytes_b = serialize_cipher(ct_b);
    auto bytes_n = serialize_cipher(ct_n);
    auto bytes_p = serialize_zero_proof(zp);

    dbg("receipt_shadow(bytes_used=" + std::to_string(bytes_used) +
        ",net=" + std::to_string(net) + "): enc_b=" +
        std::to_string(bytes_b.size()) + "B enc_n=" +
        std::to_string(bytes_n.size()) + "B proof=" +
        std::to_string(bytes_p.size()) + "B");

    return json{
        {"enc_bytes_used", with_prefix(HFHE_PREFIX, bytes_b)},
        {"enc_net",        with_prefix(HFHE_PREFIX, bytes_n)},
        {"zero_proof",     with_prefix(ZKZP_PREFIX, bytes_p)},
    };
}

json op_add(const json& req) {
    pvac_pubkey pk = deser_pubkey(req.at("pk").get<std::string>());
    GUARD(pk, pvac_free_pubkey);

    pvac_cipher a = deser_cipher(req.at("a").get<std::string>());
    GUARD(a, pvac_free_cipher);

    pvac_cipher b = deser_cipher(req.at("b").get<std::string>());
    GUARD(b, pvac_free_cipher);

    pvac_cipher out = pvac_ct_add(pk, a, b);
    if (!out) throw std::runtime_error("pvac_ct_add returned null");
    GUARD(out, pvac_free_cipher);

    auto bytes = serialize_cipher(out);
    return json{{"ct", with_prefix(HFHE_PREFIX, bytes)}};
}

// --- dispatch -----------------------------------------------------------

json process_request(const std::string& line) {
    json req;
    try {
        req = json::parse(line);
    } catch (const std::exception& e) {
        return json{{"error", std::string("bad json: ") + e.what()}};
    }

    if (!req.is_object() || !req.contains("op") || !req["op"].is_string())
        return json{{"error", "request must be object with string op"}};

    const std::string op = req["op"].get<std::string>();
    try {
        if (op == "keygen")          return op_keygen(req);
        if (op == "encrypt_zero")    return op_encrypt_zero(req);
        if (op == "encrypt_const")   return op_encrypt_const(req);
        if (op == "make_zero_proof") return op_make_zero_proof(req);
        if (op == "receipt_shadow")  return op_receipt_shadow(req);
        if (op == "add")             return op_add(req);
        if (op == "ping")            return json{{"pong", true}};
        if (op == "version")         return json{{"sidecar", "octra-pvac-sidecar/0.1"}};
        if (op == "aes_kat") {
            // Companion of webcli's compute_aes_kat_hex() — runs
            // pvac_aes_kat() (a build-time KAT of the pvac AES) and
            // hex-encodes the 16-byte result. The chain's
            // octra_registerPvacPubkey RPC requires this in the 5th
            // (kat_hex) param; without it the chain rejects with
            // "AES implementation incompatible — KAT mismatch".
            uint8_t buf[16];
            pvac_aes_kat(buf);
            static const char* HX = "0123456789abcdef";
            std::string hex(32, '0');
            for (int i = 0; i < 16; i++) {
                hex[i*2]   = HX[(buf[i] >> 4) & 0xF];
                hex[i*2+1] = HX[buf[i] & 0xF];
            }
            return json{{"kat_hex", hex}};
        }
        return json{{"error", std::string("unknown op: ") + op}};
    } catch (const std::exception& e) {
        return json{{"error", e.what()}};
    } catch (...) {
        return json{{"error", "unknown failure"}};
    }
}

}  // namespace

int main(int /*argc*/, char* /*argv*/[]) {
    // Unbuffered stdio: callers expect a response per request, with no
    // hidden buffering on either side.
    std::ios::sync_with_stdio(false);
    std::cout.setf(std::ios::unitbuf);

    dbg("ready");
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        json resp = process_request(line);
        std::cout << resp.dump() << "\n";
    }
    dbg("eof");
    return 0;
}
