// Test-only oracle: production algorithms are from the unmodified adopted pin.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out; out << std::hex << std::setfill('0');
    for (auto byte : bytes) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}
static std::vector<uint8_t> unhex(const std::string& text) {
    std::vector<uint8_t> bytes;
    if(text=="-") return bytes;
    for(size_t i=0;i<text.size();i+=2) bytes.push_back(std::stoul(text.substr(i,2),nullptr,16));
    return bytes;
}
int main() {
    pvac::Params params; params.B=7; params.m_bits=65; params.n_bits=17;
    params.h_col_wt=13; params.x_col_wt=7; params.err_wt=2;
    params.lpn_n=65; params.lpn_t=129;
    uint8_t seed[32]={}; pvac::PubKey public_key; pvac::SecKey secret_key;
    pvac::keygen_from_seed(params,public_key,secret_key,seed);
    std::string mode;
    while(std::cin >> mode) {
        bool strict,cap; size_t zeros; std::string input;
        std::cin >> strict >> cap >> zeros >> input;
        auto bytes=unhex(input); bytes.resize(bytes.size()+zeros);
        try {
            auto cipher=pvac_ser::deserialize_cipher(bytes.data(),bytes.size(),strict,cap);
            auto wire=pvac_ser::serialize_cipher(cipher);
            auto packed=pvac::compress::pack(wire);
            auto commitment=pvac::commit_ct(public_key,cipher);
            std::cout << "{\"bytes\":\"" << hex(wire) << "\",\"packed\":\"" << hex(packed)
                << "\",\"slots\":" << cipher.slots
                << ",\"compatible\":" << (pvac::is_cipher_compatible_with_pubkey(public_key,cipher) ? "true" : "false")
                << ",\"commitment\":\"" << hex(std::vector<uint8_t>(commitment.begin(),commitment.end())) << "\"}\n";
        } catch(const std::exception& error) {
            std::cout << "{\"error\":\"" << error.what() << "\"}\n";
        }
    }
}
