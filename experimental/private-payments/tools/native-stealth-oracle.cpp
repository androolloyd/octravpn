// Test-only shim around unchanged pinned Octra wallet headers and TweetNaCl.
// The linked randombytes callback is deterministic ONLY for reproducible vectors.
#include <iostream>
#include <limits>
#include "lib/stealth.hpp"

static unsigned char next_nonce_byte = 0;
extern "C" void randombytes(unsigned char* out, unsigned long long length) {
    for (unsigned long long i = 0; i < length; ++i) out[i] = next_nonce_byte++;
}
template <size_t N> std::string hex(const std::array<uint8_t, N>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string text;
    for (auto byte : bytes) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text;
}
int main() {
    std::array<uint8_t, 32> seed{}, ephemeral{}, view_secret{}, view_public{}, blind{};
    for (size_t i = 0; i < 32; ++i) { seed[i] = i; ephemeral[i] = 33 + i; blind[i] = 255 - i; }
    uint8_t ed_secret[64]{};
    std::array<uint8_t, 32> ed_public{};
    crypto_sign_keypair(ed_public.data(), ed_secret);
    if (memcmp(ed_secret, seed.data(), 32) != 0) return 3;
    octra::derive_view_keypair(ed_secret, view_secret.data(), view_public.data());
    auto shared = octra::ecdh_shared_secret(ephemeral.data(), view_public.data());
    auto secret = octra::compute_claim_secret(shared);
    const std::string recipient = "oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP";
    std::cout << "{\"seed\":\"" << hex(seed) << "\",\"ed_public\":\"" << hex(ed_public)
              << "\",\"address\":\"" << octra::derive_address_from_pubkey(ed_public.data())
              << "\",\"ephemeral_secret\":\"" << hex(ephemeral)
              << "\",\"view_secret\":\"" << hex(view_secret) << "\",\"view_public\":\"" << hex(view_public)
              << "\",\"shared\":\"" << hex(shared) << "\",\"tag\":\"" << hex(octra::compute_stealth_tag(shared))
              << "\",\"claim_secret\":\"" << hex(secret) << "\",\"recipient\":\"" << recipient
              << "\",\"claim_public\":\"" << hex(octra::compute_claim_pub(secret, recipient)) << "\",\"cases\":[";
    const uint64_t amounts[] = {0, 1, 0x0102030405060708ULL, std::numeric_limits<uint64_t>::max()};
    bool first = true;
    for (auto amount : amounts) {
        auto encrypted = octra::encrypt_stealth_amount(shared, amount, blind.data());
        auto opened = octra::decrypt_stealth_amount(shared, encrypted);
        if (!opened || opened->amount != amount || opened->blinding != blind) return 2;
        if (!first) std::cout << ',';
        first = false;
        std::cout << "{\"amount\":\"" << amount << "\",\"blinding\":\"" << hex(blind)
                  << "\",\"encrypted\":\"" << encrypted << "\",\"native_round_trip\":true}";
    }
    std::cout << "]}\n";
}
