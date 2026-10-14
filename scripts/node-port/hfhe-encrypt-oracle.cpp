// Test-only driver; encryption comes from the unmodified adopted native pin.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const uint8_t* data,size_t n) {
    std::ostringstream out; out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<n;++i) out<<std::setw(2)<<unsigned(data[i]);
    return out.str();
}
static std::array<uint8_t,32> seed(const std::string& s) {
    std::array<uint8_t,32> out{};
    for(size_t i=0;i<32;++i)out[i]=std::stoul(s.substr(i*2,2),nullptr,16);
    return out;
}
int main() {
    std::string mode,key_seed,enc_seed;
    while(std::cin>>mode>>key_seed>>enc_seed) {
        int full,profile,basis,depth; double entropy,fraction; uint64_t budget; size_t count;
        std::cin>>full>>profile>>basis>>depth>>entropy>>fraction>>budget>>count;
        std::vector<uint64_t> values(count); for(auto& value:values)std::cin>>value;
        try {
            pvac::Params p;
            if(!full){p.m_bits=65;p.n_bits=17;p.h_col_wt=13;p.x_col_wt=7;p.err_wt=2;p.lpn_n=65;p.lpn_t=127;}
            p.B=basis;p.noise_entropy_bits=entropy;p.tuple2_fraction=fraction;p.edge_budget=budget;
            pvac::PubKey pk;pvac::SecKey sk;
            auto ks=seed(key_seed),es=seed(enc_seed);
            pvac::keygen_from_seed(p,pk,sk,ks.data());
            pvac::set_circuit_prf_profile(pk,sk,static_cast<pvac::CircuitPrfProfile>(profile));
            pvac::Cipher cipher;
            if(mode=="pipeline") {
                auto a=pvac::enc_values_seeded(pk,sk,values,es.data());
                auto other_seed=es;for(auto& byte:other_seed)byte^=255;
                auto b=pvac::enc_values_seeded(pk,sk,values,other_seed.data());
                auto c=pvac::ct_add_const(pk,a,uint64_t(5),true);
                auto d=pvac::ct_mul_const(pk,b,uint64_t(3));
                auto e=pvac::ct_mul_seeded(pk,c,d,es.data(),8,true);
                auto f=pvac::ct_square_seeded(pk,e,es.data(),4,true);
                cipher=pvac::ct_sub(pk,pvac::ct_div_const(pk,f,pvac::fp_from_u64(7)),a);
                pvac::ubk_apply(pk,cipher);
            }
            else if(mode=="value")cipher=pvac::enc_value_seeded(pk,sk,values.at(0),es.data());
            else if(mode=="value_depth")cipher=pvac::enc_value_depth_seeded(pk,sk,values.at(0),depth,es.data());
            else if(mode=="values")cipher=pvac::enc_values_seeded(pk,sk,values,es.data());
            else if(mode=="zero")cipher=pvac::enc_zero_seeded(pk,sk,es.data());
            else {std::vector<pvac::Fp> fields;for(auto v:values)fields.push_back(pvac::fp_from_u64(v));auto rng=pvac::make_seeded_rng(es.data());cipher=pvac::enc_fp_depth_seeded(pk,sk,fields,depth,rng);}
            auto bytes=pvac_ser::serialize_cipher(cipher);
            auto clear=pvac::dec_values(pk,sk,cipher);
            auto noise=pvac::plan_noise(pk,depth);
            std::cout<<"{\"wire\":\""<<hex(bytes.data(),bytes.size())<<"\",\"noise\":["<<noise.first<<','<<noise.second<<"],\"clear\":[";
            for(size_t i=0;i<clear.size();++i){uint8_t b[16];pvac::store_le64(b,clear[i].lo);pvac::store_le64(b+8,clear[i].hi);if(i)std::cout<<',';std::cout<<'"'<<hex(b,16)<<'"';}
            std::cout<<"]}\n";
        }catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
    }
}
