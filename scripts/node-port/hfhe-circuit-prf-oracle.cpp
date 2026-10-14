// Test-only driver. Algorithms are provided by the unmodified adopted PVAC pin.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const uint8_t* bytes, size_t size) {
    std::ostringstream out; out << std::hex << std::setfill('0');
    for (size_t i=0;i<size;++i) out << std::setw(2) << unsigned(bytes[i]);
    return out.str();
}
static std::string fp(pvac::Fp value) {
    uint8_t bytes[16]; pvac::store_le64(bytes,value.lo); pvac::store_le64(bytes+8,value.hi);
    return hex(bytes,16);
}
static std::string scalar(const pvac::Scalar& value) {
    uint8_t bytes[32]; pvac::sc_tobytes(bytes,value); return hex(bytes,32);
}
static std::vector<uint8_t> unhex(const std::string& value) {
    std::vector<uint8_t> out;
    for(size_t i=0;i<value.size();i+=2) out.push_back(std::stoul(value.substr(i,2),nullptr,16));
    return out;
}
template<class T, class F> static void array(const char* name,const std::vector<T>& values,F encode) {
    std::cout << ",\"" << name << "\":[";
    for(size_t i=0;i<values.size();++i) { if(i)std::cout << ','; std::cout << '"' << encode(values[i]) << '"'; }
    std::cout << ']';
}
int main() {
    std::string mode;
    while(std::cin >> mode) {
        try {
            if(mode=="round") {
                unsigned profile; size_t round; uint64_t lo,hi;
                std::cin >> profile >> round >> lo >> hi;
                auto p=static_cast<pvac::CircuitPrfProfile>(profile);
                auto constant=pvac::circuit_prf_round_constant(p,round);
                std::cout << "{\"constant\":\"" << fp(constant) << "\",\"power\":\""
                    << fp(pvac::circuit_prf_power(p,pvac::fp_from_words(lo,hi))) << "\",\"version\":\""
                    << pvac::circuit_prf_proof_version(p) << "\",\"rounds\":" << pvac::circuit_prf_rounds(p) << "}\n";
            } else if(mode=="toep") {
                size_t bits,nt,ny; std::cin >> bits >> nt >> ny;
                std::vector<uint64_t> top(nt),y(ny);
                for(auto& v:top)std::cin >> v;
                for(auto& v:y)std::cin >> v;
                uint64_t lo,hi; pvac::toep_127_full(top,y,bits,lo,hi);
                uint8_t bytes[16]; pvac::store_le64(bytes,lo); pvac::store_le64(bytes+8,hi);
                std::cout << "{\"bits\":\"" << hex(bytes,16) << "\"}\n";
            } else if(mode=="case") {
                std::string seed; unsigned profile,kind; size_t count,index; uint32_t gid;
                uint64_t tag,lo,hi; int n,t,num,den;
                std::cin >> seed >> profile >> n >> t >> num >> den >> tag >> lo >> hi >> count >> index >> gid >> kind;
                auto bytes=unhex(seed);
                pvac::Params prm; prm.m_bits=65; prm.n_bits=17; prm.h_col_wt=13; prm.x_col_wt=7; prm.err_wt=2;
                prm.lpn_n=n; prm.lpn_t=t; prm.lpn_tau_num=num; prm.lpn_tau_den=den;
                pvac::PubKey pk; pvac::SecKey sk; pvac::keygen_from_seed(prm,pk,sk,bytes.data());
                pvac::set_circuit_prf_profile(pk,sk,static_cast<pvac::CircuitPrfProfile>(profile));
                pvac::Layer layer{}; layer.seed={tag,{lo,hi}};
                auto masks=pvac::circuit_prf_R_slots(pk,sk,layer.seed,count);
                auto delta=pvac::delta::Gen{pk,sk,layer.seed};
                std::cout << "{\"challenge\":\"" << fp(pvac::circuit_prf_challenge(pk,layer.seed,index))
                    << "\",\"r\":\"" << fp(pvac::circuit_prf_R(pk,sk,layer.seed,index))
                    << "\",\"rho_prod\":\"" << scalar(pvac::derive_rho_prod(sk,layer,index))
                    << "\",\"r_alpha\":\"" << scalar(pvac::derive_r_alpha(sk,layer,index)) << '"';
                array("masks",masks,fp);
                auto delta_values=delta.per_slot(gid,static_cast<uint8_t>(kind),count);
                array("delta",delta_values,fp);
                std::cout << ",\"scalar_delta\":\"" << fp(delta.scalar(gid,static_cast<uint8_t>(kind))) << '"';
                std::cout << ",\"noise_core\":\"" << fp(pvac::lpn_v2::core(pk,sk,layer.seed,pvac::lpn_v2::N1)) << '"';
                std::cout << ",\"noise\":\"" << fp(pvac::lpn_v2::noise(pk,sk,layer.seed)) << '"';
                auto commitment=pvac::compute_R_com_base(pk.canon_tag,tag,lo,hi,masks);
                std::cout << ",\"base_commitment\":\"" << hex(commitment.data(),32) << '"';
                auto product=pvac::compute_R_com_prod(commitment,pk.circuit_prf_key_commit);
                std::cout << ",\"product_commitment\":\"" << hex(product.data(),32) << '"';
                pvac::compute_layer_PC(layer,sk,masks,count);
                auto point=[](const std::array<uint8_t,32>& v){return hex(v.data(),32);};
                array("r_pc",layer.R_PC,point); array("pc",layer.PC,point);
                pvac::compute_prod_layer_PC(layer,sk,masks,delta_values,count);
                array("product_pc",layer.PC,point);
                std::cout << ",\"nonzero\":" << (pvac::circuit_prf_slots_nonzero(masks) ? "true" : "false") << "}\n";
            }
        } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
    }
}
