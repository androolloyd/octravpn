// Test-only oracle over the unmodified pinned C++ field implementation.
#include "pvac/core/field.hpp"
#include <iostream>
#include <iomanip>

static void hex(pvac::Fp value) {
    const uint64_t words[] = {value.lo, value.hi};
    std::cout << std::hex << std::setfill('0');
    for (uint64_t word : words) for (int i = 0; i < 8; ++i)
        std::cout << std::setw(2) << ((word >> (i * 8)) & 255);
    std::cout << std::dec;
}
int main() {
    uint64_t a0, a1, b0, b1, exponent;
    while (std::cin >> a0 >> a1 >> b0 >> b1 >> exponent) {
        auto a = pvac::fp_from_words(a0, a1); auto b = pvac::fp_from_words(b0, b1);
        hex(a); std::cout << ' '; hex(b); std::cout << ' ';
        hex(pvac::fp_add(a,b)); std::cout << ' '; hex(pvac::fp_sub(a,b)); std::cout << ' ';
        hex(pvac::fp_neg(a)); std::cout << ' '; hex(pvac::fp_mul(a,b)); std::cout << ' ';
        hex(pvac::fp_pow_u64(a,exponent)); std::cout << ' '; hex(pvac::fp_inv(a)); std::cout << ' ';
        int64_t signed_value;
        if (pvac::fp_to_i64(a, signed_value)) std::cout << signed_value;
        else std::cout << "none";
        std::cout << '\n';
    }
}
