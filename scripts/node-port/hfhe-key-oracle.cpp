// Test-only oracle. All algorithms come from the unmodified adopted PVAC tree.
#include "pvac_serialize.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

static std::string hex(const uint8_t* bytes, size_t size) {
    std::ostringstream output; output << std::hex << std::setfill('0');
    for (size_t i=0;i<size;++i) output << std::setw(2) << static_cast<unsigned>(bytes[i]);
    return output.str();
}
static std::string hash(const std::vector<uint8_t>& bytes) {
    uint8_t digest[32]; pvac::sha256_bytes(bytes.data(),bytes.size(),digest);
    return hex(digest,32);
}
static std::vector<uint8_t> unhex(const std::string& value) {
    std::vector<uint8_t> bytes;
    for (size_t i=0;i<value.size();i+=2) bytes.push_back(std::stoul(value.substr(i,2),nullptr,16));
    return bytes;
}
int main() {
    std::string mode;
    while (std::cin >> mode) {
        if(mode=="toep") {
            size_t na, nb; std::cin >> na >> nb;
            std::vector<uint64_t> top(na),y(nb);
            for(auto& word:top)std::cin >> word;
            for(auto& word:y)std::cin >> word;
            uint64_t lo,hi; uint8_t bytes[16];
            pvac::toep_127_scalar(top,y,lo,hi);
            pvac::store_le64(bytes,lo); pvac::store_le64(bytes+8,hi);
            std::cout << "{\"scalar\":\"" << hex(bytes,16) << '"';
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
            pvac::toep_127_pmull(top,y,lo,hi);
#elif defined(__PCLMUL__)
            pvac::toep_127_clmul(top,y,lo,hi);
#endif
            pvac::store_le64(bytes,lo); pvac::store_le64(bytes+8,hi);
            std::cout << ",\"hardware\":\"" << hex(bytes,16) << "\"}\n";
        } else if(mode=="lpn") {
            std::string seed_hex; int n,t,num,den; uint64_t tag,lo,hi;
            std::cin >> seed_hex >> n >> t >> num >> den >> tag >> lo >> hi;
            auto bytes=unhex(seed_hex);
            pvac::Params prm; prm.m_bits=65; prm.n_bits=17; prm.h_col_wt=13; prm.x_col_wt=7; prm.err_wt=2;
            prm.lpn_n=n; prm.lpn_t=t; prm.lpn_tau_num=num; prm.lpn_tau_den=den;
            pvac::PubKey pk; pvac::SecKey sk; pvac::keygen_from_seed(prm,pk,sk,bytes.data());
            pvac::g_toep = pvac::toep_127_scalar;
            pvac::RSeed seed{tag,{lo,hi}};
            std::vector<uint64_t> y; pvac::lpn_make_ybits(pk,sk,seed,pvac::Dom::PRF_R1,y);
            std::vector<uint8_t> raw(y.size()*8);
            for(size_t i=0;i<y.size();++i)pvac::store_le64(raw.data()+8*i,y[i]);
            std::cout << "{\"y\":\"" << hex(raw.data(),raw.size()) << '"';
            auto field=[&](const char* name,pvac::Fp value) {
                uint8_t out[16]; pvac::store_le64(out,value.lo); pvac::store_le64(out+8,value.hi);
                std::cout << ",\"" << name << "\":\"" << hex(out,16) << '"';
            };
            field("core",pvac::prf_R_core(pk,sk,seed,pvac::Dom::PRF_R1));
            field("r",pvac::prf_R(pk,sk,seed));
            field("noise",pvac::prf_R_noise(pk,sk,seed));
            std::cout << "}\n";
        } else if (mode=="key" || mode=="key_v6") {
            std::string seed_hex;
            pvac::Params prm;
            std::cin >> seed_hex >> prm.B >> prm.m_bits >> prm.n_bits >> prm.h_col_wt >> prm.x_col_wt >> prm.err_wt >> prm.lpn_n >> prm.lpn_t >> prm.lpn_tau_den;
            auto seed=unhex(seed_hex);
            try {
                pvac::PubKey pk; pvac::SecKey sk;
                pvac::keygen_from_seed(prm,pk,sk,seed.data());
                if(mode=="key_v6") pvac::set_circuit_prf_profile(pk,sk,pvac::CircuitPrfProfile::MIMC_X3_V6);
                auto raw=pvac_ser::serialize_pubkey_raw(pk);
                auto packed=pvac_ser::serialize_pubkey(pk);
                auto secret=pvac_ser::serialize_seckey(sk);
                auto generator=pvac::rist_H();
                std::cout << "{\"raw_sha256\":\"" << hash(raw) << "\",\"packed_sha256\":\"" << hash(packed)
                    << "\",\"raw_length\":" << raw.size() << ",\"packed_length\":" << packed.size()
                    << ",\"secret\":\"" << hex(secret.data(),secret.size()) << "\",\"h_generator\":\"" << hex(generator.data(),32)
                    << "\",\"h_digest\":\"" << hex(pk.H_digest.data(),32) << "\",\"commitment\":\"" << hex(pk.circuit_prf_key_commit.data(),32) << '"';
                if(raw.size()<65536) std::cout << ",\"raw\":\"" << hex(raw.data(),raw.size()) << "\",\"packed\":\"" << hex(packed.data(),packed.size()) << '"';
                std::cout << "}\n";
            } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
        } else if(mode=="import_pub" || mode=="import_sec") {
            std::string bytes_hex; std::cin >> bytes_hex;
            auto bytes=unhex(bytes_hex=="-" ? "" : bytes_hex);
            try {
                std::vector<uint8_t> result;
                if(mode=="import_pub") result=pvac_ser::serialize_pubkey_raw(pvac_ser::deserialize_pubkey(bytes.data(),bytes.size()));
                else result=pvac_ser::serialize_seckey(pvac_ser::deserialize_seckey(bytes.data(),bytes.size()));
                std::cout << "{\"bytes\":\"" << hex(result.data(),result.size()) << "\"}\n";
            } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
        } else if(mode=="pack" || mode=="unpack") {
            std::string bytes_hex; std::cin >> bytes_hex;
            auto bytes=unhex(bytes_hex=="-" ? "" : bytes_hex);
            try {
                auto result = mode=="pack" ? pvac::compress::pack(bytes) : pvac::compress::unpack(bytes);
                std::cout << "{\"bytes\":\"" << hex(result.data(),result.size()) << "\"}\n";
            } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
        } else if(mode=="matrix") {
            int k,n; size_t factor; uint64_t tag;
            std::cin >> k >> n >> factor >> tag;
            try {
                auto sampled=pvac::prg_choose_k(k,n,"pvac.dom.h_gen",{0,tag,UINT64_MAX},factor);
                std::cout << "{\"indices\":[";
                for(size_t i=0;i<sampled.size();++i) { if(i)std::cout << ','; std::cout << sampled[i]; }
                std::cout << "]}\n";
            } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
        }
    }
}
