// Test-only oracle; all product algorithms are the unmodified adopted PVAC code.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out; out << std::hex << std::setfill('0');
    for (auto byte : bytes) out << std::setw(2) << unsigned(byte);
    return out.str();
}
static std::vector<uint8_t> unhex(const std::string& text) {
    std::vector<uint8_t> result;
    for (size_t i=0; i<text.size(); i+=2) result.push_back(std::stoul(text.substr(i,2),nullptr,16));
    return result;
}
static pvac::Cipher sample(size_t slots, int kind, uint64_t tweak) {
    pvac::Cipher c; c.slots=slots;
    if(kind!=3 && kind!=9) {
        for(size_t j=0;j<slots;++j)c.c0.push_back(pvac::fp_from_u64(tweak+j+3));
    }
    if(kind==4 || kind==9)return c;
    const size_t layers=kind==1 ? 2 : kind==2 || kind==6 ? 3 : 1;
    for(size_t i=0;i<layers;++i) {
        pvac::Layer l{};l.rule=pvac::RRule::BASE;
        l.seed={tweak+11+i,{tweak+19+i,UINT64_MAX-i}};
        l.R_com.fill(uint8_t(tweak+37+i));
        if(kind==2 && i==2) {l.rule=pvac::RRule::PROD;l.pa=0;l.pb=1;}
        c.L.push_back(l);
    }
    if(kind==5)return c;
    const size_t edge_layers=kind==6 ? 1 : layers;
    for(size_t i=0;i<edge_layers;++i) {
        for(size_t k=0;k<2;++k) {
            pvac::Edge e; e.layer_id=uint32_t(i);e.idx=kind==7 ? 21 : uint16_t((i+k+tweak)%21);
            e.ch=uint8_t(k);
            for(size_t j=0;j<slots;++j) {
                auto v=pvac::fp_from_u64((tweak+1)*(i+2)*(j+3)+k);
                e.w.push_back((i+j)%2 ? pvac::fp_neg(v) : v);
            }
            e.s.nbits=kind==8 ? 64 : 65;e.s.w={tweak+i+k};
            if(kind!=8)e.s.w.push_back(k&1);
            c.E.push_back(e);
        }
    }
    return c;
}
int main() {
    pvac::Params p; p.B=21;p.m_bits=65;p.n_bits=17;p.h_col_wt=13;p.x_col_wt=7;p.err_wt=2;
    p.lpn_n=65;p.lpn_t=129;
    uint8_t wallet_seed[32]={};pvac::PubKey pk;pvac::SecKey sk;
    pvac::keygen_from_seed(p,pk,sk,wallet_seed);
    std::string mode,seed_hex;
    while(std::cin >> mode >> seed_hex) {
        size_t slots_a,slots_b,repack,draw;int kind_a,kind_b,math,rounds,error_weight;uint64_t budget;
        std::cin >> slots_a >> slots_b >> kind_a >> kind_b >> math >> repack >> draw >> budget >> rounds >> error_weight;
        auto seed=unhex(seed_hex);if(seed.size()!=32)return 1;
        pk.prm.edge_budget=budget;pk.prm.err_wt=error_weight;
        auto a=sample(slots_a,kind_a,5),b=sample(slots_b,kind_b,13);
        std::cout << "{\"public\":\"" << hex(pvac_ser::serialize_pubkey_raw(pk))
            << "\",\"left\":\"" << hex(pvac_ser::serialize_cipher(a))
            << "\",\"right\":\"" << hex(pvac_ser::serialize_cipher(b)) << "\",\"expected\":";
        try {
            auto result=a;
            for(int i=0;i<rounds;++i) {
                if(mode=="mul") result=pvac::ct_mul_seeded(pk,result,b,seed.data(),repack,math,draw);
                else result=pvac::ct_square_seeded(pk,result,seed.data(),repack,math);
            }
            std::cout << "{\"bytes\":\"" << hex(pvac_ser::serialize_cipher(result)) << "\"}";
        } catch(const std::exception& error) {std::cout << "{\"error\":\"" << error.what() << "\"}";}
        std::cout << "}\n";
    }
}
