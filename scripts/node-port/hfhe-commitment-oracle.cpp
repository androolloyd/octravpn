// Test-only oracle using the unmodified adopted C++ commitment implementation.
#include "pvac/crypto/ristretto255.hpp"
#include <iomanip>
#include <iostream>
#include <string>

static uint8_t byte_at(const std::string& hex, size_t offset) {
    return static_cast<uint8_t>(std::stoul(hex.substr(offset * 2, 2), nullptr, 16));
}

int main() {
    std::string value_hex, blind_hex;
    while (std::cin >> value_hex >> blind_hex) {
        if (value_hex.size() != 32 || blind_hex.size() != 64) return 1;
        pvac::Fp value{};
        uint8_t blind[32];
        for (size_t i = 0; i < 8; ++i) {
            value.lo |= uint64_t(byte_at(value_hex, i)) << (i * 8);
            value.hi |= uint64_t(byte_at(value_hex, i + 8)) << (i * 8);
        }
        if (!pvac::fp_is_reduced(value)) return 1;
        for (size_t i = 0; i < 32; ++i) blind[i] = byte_at(blind_hex, i);
        const auto point = pvac::pedersen_commit(
            pvac::sc_from_fp_signed(value), pvac::sc_reduce256(blind));
        std::cout << std::hex << std::setfill('0');
        for (uint8_t byte : point) std::cout << std::setw(2) << unsigned(byte);
        std::cout << '\n';
    }
}
