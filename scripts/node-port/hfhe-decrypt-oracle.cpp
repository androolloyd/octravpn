// Test-only decryption driver against the pristine adopted PVAC implementation.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const uint8_t* bytes,size_t size) {
    std::ostringstream out; out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<size;++i)out<<std::setw(2)<<unsigned(bytes[i]);
    return out.str();
}
static std::string fp(pvac::Fp value) {
    uint8_t bytes[16]; pvac::store_le64(bytes,value.lo);pvac::store_le64(bytes+8,value.hi);return hex(bytes,16);
}
static std::vector<uint8_t> unhex(const std::string& value) {
    std::vector<uint8_t> out;
    for(size_t i=0;i<value.size();i+=2)out.push_back(std::stoul(value.substr(i,2),nullptr,16));
    return out;
}
static void fields(const std::vector<pvac::Fp>& values) {
    std::cout<<'[';
    for(size_t j=0;j<values.size();++j){if(j)std::cout<<',';std::cout<<'"'<<fp(values[j])<<'"';}
    std::cout<<']';
}
static std::vector<uint8_t> wire_unchecked(const pvac::Cipher& c) {
    pvac_ser::Writer w;w.header(pvac_ser::TAG_CIPHER);w.u64(c.slots);w.u64(c.L.size());
    for(const auto& l:c.L)pvac_ser::write_layer(w,l);
    w.u64(c.c0.size());for(const auto& v:c.c0)w.fp(v);
    w.u64(c.E.size());for(const auto& e:c.E)pvac_ser::write_edge(w,e);
    return std::move(w.buf);
}
int main() {
    std::string seed_hex,kind; unsigned profile; size_t slots; uint64_t lo,hi;
    while(std::cin>>seed_hex>>profile>>slots>>kind>>lo>>hi) {
        auto seed=unhex(seed_hex);pvac::Params prm;
        prm.m_bits=65;prm.n_bits=17;prm.h_col_wt=13;prm.x_col_wt=7;prm.err_wt=2;prm.lpn_n=65;prm.lpn_t=129;
        pvac::PubKey pk;pvac::SecKey sk;pvac::keygen_from_seed(prm,pk,sk,seed.data());
        pvac::set_circuit_prf_profile(pk,sk,static_cast<pvac::CircuitPrfProfile>(profile));
        pvac::g_toep=pvac::toep_127_scalar;
        pvac::Cipher c;c.slots=slots;
        for(size_t j=0;j<slots;++j)c.c0.push_back(j%2 ? pvac::fp_neg(pvac::fp_from_u64(j+5)) : pvac::fp_from_u64(j+5));
        auto base=[&](uint64_t offset,bool active,bool native) {
            pvac::Layer layer{};layer.rule=pvac::RRule::BASE;
            layer.seed.nonce={lo+offset,hi-offset};
            layer.seed.ztag=native ? pvac::ru_ztag(pk.canon_tag,layer.seed.nonce) : pvac::prg_layer_ztag(pk.canon_tag,layer.seed.nonce);
            if(active) {
                auto r=pvac::circuit_prf_R_slots(pk,sk,layer.seed,slots);
                pvac::compute_layer_PC(layer,sk,r,slots);
            }
            c.L.push_back(layer);
        };
        auto product=[&](uint32_t a,uint32_t b) {
            pvac::Layer layer{};layer.rule=pvac::RRule::PROD;layer.pa=a;layer.pb=b;c.L.push_back(layer);
        };
        if(kind!="empty" && kind!="clear") {
            bool legacy=kind=="legacy" || kind=="pc_only";
            bool native=kind=="native" || kind=="native_unused" || kind=="native_tag_flip";
            base(0,!legacy,native);
            if(kind=="pc_only")c.L[0].PC.resize(slots);
            if(kind=="r_pc_only")c.L[0].PC.clear();
            if(kind=="native_tag_flip")c.L[0].seed.ztag^=1;
            if(kind=="product" || kind=="native_product" || kind=="nested" || kind=="bad_parent") {
                base(7,false,kind=="native_product");product(0,1);
                if(kind=="nested") { product(2,0);product(2,3); }
            }
            for(size_t i=0;i<c.L.size();++i) {
                if(kind=="native_unused")break;
                pvac::Edge e{};e.layer_id=i;e.idx=(i*17+3)%prm.B;e.ch=i%2;
                for(size_t j=0;j<slots;++j)e.w.push_back(pvac::fp_from_words(j+3,((i+j)%3)==0 ? (1ull<<62) : 0));
                e.s=pvac::BitVec::make(prm.m_bits);c.E.push_back(e);
            }
        }
        if(kind=="empty")c.c0.clear();
        if(kind=="implicit_zero")c.c0.clear();
        if(kind=="wrong_sigma")c.E[0].s=pvac::BitVec::make(prm.m_bits-1);
        if(kind=="wrong_index")c.E[0].idx=prm.B;
        if(kind=="bad_parent")c.L.back().pa=c.L.size()-1;
        if(kind=="bad_sign")c.E[0].ch=2;
        if(kind=="bad_weights")c.E[0].w.clear();
        if(kind=="bad_c0")c.c0.push_back(pvac::fp_from_u64(0));
        auto raw=wire_unchecked(c);
        std::cout<<"{\"bytes\":\""<<hex(raw.data(),raw.size())<<"\",\"native_tag\":\""<<pvac::ru_ztag(pk.canon_tag,{lo,hi})<<'"';
        auto tag=pvac::ru_ztag(pk.canon_tag,{lo,hi});
        auto affine=pvac::ru_affine(sk,{tag,{lo,hi}},SIZE_MAX);
        std::cout<<",\"native_affine\":\""<<fp(affine)<<"\",\"native_masks\":";
        fields(pvac::ru_r_slots(sk,{tag,{lo,hi}},slots));
        try { (void)pvac_ser::deserialize_cipher(raw.data(),raw.size());std::cout<<",\"import_error\":null"; }
        catch(const std::exception& error){std::cout<<",\"import_error\":\""<<error.what()<<'"';}
        std::cout<<",\"native_source\":"<<(pvac::dec_has_native_src(pk,c)?"true":"false")<<",\"policies\":[";
        for(unsigned policy=0;policy<3;++policy) {
            if(policy)std::cout<<',';
            auto p=static_cast<pvac::DecPolicy>(policy);
            std::cout<<'{';
            try {auto values=pvac::dec_values(pk,sk,c,p);std::cout<<"\"values\":";fields(values);}
            catch(const std::exception& error){std::cout<<"\"values_error\":\""<<error.what()<<'"';}
            try {auto v=pvac::dec_value(pk,sk,c,p);std::cout<<",\"value\":\""<<fp(v)<<'"';}
            catch(const std::exception& error){std::cout<<",\"value_error\":\""<<error.what()<<'"';}
            try {auto v=pvac::dec_value_slot0(pk,sk,c,p);std::cout<<",\"slot0\":\""<<fp(v)<<'"';}
            catch(const std::exception& error){std::cout<<",\"slot0_error\":\""<<error.what()<<'"';}
            std::cout<<'}';
        }
        std::cout<<"]}\n";
    }
}
