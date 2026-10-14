// Test-only oracle over the unmodified pinned AES counter/RNG code.
#include "pvac/core/seedable_rng.hpp"
#include <iostream>
#include <iomanip>

static void hex(const uint8_t* data, size_t size) {
    std::cout << std::hex << std::setfill('0');
    for (size_t i=0;i<size;++i) std::cout << std::setw(2) << static_cast<unsigned>(data[i]);
    std::cout << std::dec;
}
int main() {
    std::string key_hex; uint64_t nonce;
    while (std::cin >> key_hex >> nonce) {
        uint8_t key[32];
        for (size_t i=0;i<32;++i) key[i]=std::stoul(key_hex.substr(i*2,2),nullptr,16);
        pvac::AesCtr256 rng; rng.init(key,nonce);
        std::cout << rng.next_u64() << ' ';
        uint64_t block[5]; rng.fill_u64(block,5);
        for (auto value:block) std::cout << value << ' ';
        for (uint64_t maximum:{0ull,1ull,2ull,3ull,337ull,8192ull,0x8000000000000001ull,UINT64_MAX})
            std::cout << rng.bounded(maximum) << ' ';
        std::cout << rng.next_u64() << ' ';
        pvac::SeedableRng seeded; seeded.init(key);
        auto value=seeded.fp_nonzero();
        uint8_t field[16]; pvac::store_le64(field,value.lo); pvac::store_le64(field+8,value.hi); hex(field,16);
        auto seed_nonce=seeded.nonce128(); std::cout << ' ' << seed_nonce.lo << ' ' << seed_nonce.hi << ' ';
        pvac::PubKey pk; pvac::SecKey sk;
        sk.prf_k={1,2,3,UINT64_MAX}; pk.canon_tag=nonce;
        std::memcpy(pk.H_digest.data(),key,32);
        pvac::RSeed seed{337,{nonce,UINT64_MAX}};
        uint8_t derived[32]; uint64_t derived_nonce;
        pvac::derive_aes_key(pk,sk,seed,pvac::Dom::PRF_R1,derived,derived_nonce);
        hex(derived,32); std::cout << ' ' << derived_nonce << '\n';
    }
}
