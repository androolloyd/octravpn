#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace pvac;
static std::string hex(const uint8_t* bytes,size_t size){std::ostringstream s;s<<std::hex<<std::setfill('0');for(size_t i=0;i<size;++i)s<<std::setw(2)<<unsigned(bytes[i]);return s.str();}
static std::string hex(const std::array<uint8_t,32>& bytes){return hex(bytes.data(),bytes.size());}
int main(){int profile,mutation,adm;size_t queries;double noise;
 while(std::cin>>profile>>mutation>>adm>>queries>>noise){try {
 Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=noise;
 uint8_t seed[32];for(int i=0;i<32;++i)seed[i]=i;PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,seed);set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile));
 auto key=make_rku(pk,sk,queries,nat_prod_budget());auto admission=nat_adm();
 switch(adm){case 1:admission=nat_lin();break;case 2:admission=nat_wide();break;case 3:admission=nat_vec4();break;case 4:admission=nat_vec8();break;case 5:admission=nat_prod_adm();break;case 6:admission.max_terms=0;break;case 7:admission.out_terms=17;break;case 8:admission.max_slots=9;break;case 9:admission.max_query=65;break;case 10:admission.alpha_bits=9;break;case 11:admission.row_bits=0;break;}
 std::cout<<"{\"public\":\""<<hex(native_runtime_pubkey_digest(pk))<<"\",\"secret\":\""<<hex(native_runtime_seckey_digest(pk,sk))<<"\",\"domain\":\""<<hex(key.dom)<<"\",\"view\":\""<<hex(key.view)<<"\",\"ciphertexts\":[";
 for(size_t i=0;i<key.sec.size();++i){if(i)std::cout<<',';auto bytes=pvac_ser::serialize_cipher(key.sec[i]);std::cout<<'"'<<hex(bytes.data(),bytes.size())<<'"';}
 switch(mutation){case 1:key.key[0]^=1;break;case 2:key.dom[0]^=1;break;case 3:key.view[0]^=1;break;case 4:key.safe=false;break;case 5:key.prf=3;break;case 6:key.lpn=1;break;case 7:key.sec.pop_back();break;case 8:key.sec[0]=Cipher{};break;case 9:key.policy.reusable=false;break;case 10:key.policy.hidden_output=false;break;case 11:key.policy.statement_bound=false;break;case 12:key.policy.transcript_bound=false;break;case 13:key.policy.material_bound=false;break;case 14:key.policy.no_basis_oracle=false;break;case 15:key.policy.native_backend=false;break;case 16:key.policy.max_queries=0;break;case 17:key.policy.cert=HiddenCoeffCertKind::NONE;break;case 18:key.budget.proof=NativeResetProofProfileKind::SHA_COMPAT;break;case 19:key.budget.target_bits=127;break;case 20:key.budget.max_trace_units=1025;break;case 21:key.budget.max_output_tags=65;break;case 22:key.budget.max_proof_bytes=(1<<20)+1;break;case 23:key.budget.max_trace_units=0;break;case 24:key.budget.max_output_tags=0;break;case 25:key.budget.max_proof_bytes=0;break;case 26:key.policy.max_queries=65;break;case 27:key.budget=NativeRuntimeReusableBudget{};break;}
 auto gate=nat_prod_gate(pk,key,admission);
 std::cout<<"],\"mutated_view\":\""<<hex(rku_view(pk,key))<<"\",\"safe\":"<<rku_safe(pk,key)<<",\"profile\":\""<<hex(nat_profile_digest(admission))<<"\",\"gate\":["<<gate.admitted<<','<<gate.key<<','<<gate.profile<<','<<gate.budget<<','<<gate.rejects_key<<','<<gate.rejects_profile<<','<<gate.rejects_budget<<','<<gate.rejects_sha_compat<<','<<gate.rejects_underbudget<<','<<gate.rejects_trace_wide<<','<<gate.rejects_output_wide<<','<<gate.rejects_proof_wide<<"]}\n";
 }catch(const std::exception& e){std::cout<<"{\"error\":\""<<e.what()<<"\"}\n";}}
}
