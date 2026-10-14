// Test-only oracle: retained and wide scalar arithmetic from the adopted pin.
#include "pvac/crypto/ristretto255.hpp"
#include <iomanip>
#include <iostream>
#include <string>

static void hex(const pvac::Scalar& scalar) {
    uint8_t bytes[32]; pvac::sc_tobytes(bytes,scalar);
    std::cout << std::hex << std::setfill('0');
    for (auto byte:bytes) std::cout << std::setw(2) << unsigned(byte);
    std::cout << std::dec;
}
static uint64_t word(const std::string& text,size_t index) {
    uint64_t value=0;
    for(size_t i=0;i<8;++i)value|=uint64_t(std::stoul(text.substr((index*8+i)*2,2),nullptr,16))<<(8*i);
    return value;
}
int main() {
    std::string mode,first,second;
    while(std::cin >> mode >> first) {
        if(mode=="reduce") {
            if(first.size()!=128)return 1;
            uint64_t words[8];for(size_t i=0;i<8;++i)words[i]=word(first,i);
            hex(pvac::sc_reduce512(words,pvac::ScalarRule::Prior));std::cout << ' ';
            hex(pvac::sc_reduce512(words,pvac::ScalarRule::Wide));std::cout << '\n';
        } else if(mode=="arithmetic") {
            std::cin >> second;if(first.size()!=64 || second.size()!=64)return 1;
            pvac::Scalar a{},b{};
            for(size_t i=0;i<4;++i){a.v[i]=word(first,i);b.v[i]=word(second,i);}
            std::cout << pvac::sc_is_canonical(a) << ' ' << pvac::sc_is_canonical(b) << ' ';
            hex(pvac::sc_add(a,b));std::cout << ' ';
            hex(pvac::sc_sub(a,b));std::cout << ' ';
            hex(pvac::sc_neg(a));std::cout << ' ';
            hex(pvac::sc_mul(a,b,pvac::ScalarRule::Prior));std::cout << ' ';
            hex(pvac::sc_mul(a,b,pvac::ScalarRule::Wide));std::cout << ' ';
            hex(pvac::sc_inv(a,pvac::ScalarRule::Prior));std::cout << ' ';
            hex(pvac::sc_inv(a,pvac::ScalarRule::Wide));std::cout << ' ';
            uint8_t bytes[32];pvac::sc_tobytes(bytes,a);
            hex(pvac::sc_reduce256(bytes));std::cout << '\n';
        } else if(mode=="field") {
            if(first.size()!=32)return 1;
            pvac::Fp value{word(first,0),word(first,1)};
            if(!pvac::fp_is_reduced(value))return 1;
            hex(pvac::sc_from_fp(value));std::cout << ' ';
            hex(pvac::sc_from_fp_signed(value));std::cout << '\n';
        } else return 1;
    }
}
