#include <cstdint>
// Test-only entropy tape adapter; adopted PVAC headers remain unmodified.
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#if defined(__linux__)
#include <sys/random.h>
#endif
static uint64_t entropy_state = 0, entropy_word = 0;
static size_t consumed = 0, calls = 0, entropy_available = 0;
static void fixture_random(void* destination, size_t count) {
    ++calls; consumed += count; auto out=static_cast<unsigned char*>(destination);
    for(size_t i=0;i<count;i++) {
        if(!entropy_available) {
            entropy_state += UINT64_C(0x9e3779b97f4a7c15);
            uint64_t value=entropy_state;
            value=(value^(value>>30))*UINT64_C(0xbf58476d1ce4e5b9);
            value=(value^(value>>27))*UINT64_C(0x94d049bb133111eb);
            entropy_word=value^(value>>31);entropy_available=8;
        }
        out[i]=entropy_word&255;entropy_word>>=8;--entropy_available;
    }
}
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define arc4random_buf fixture_random
#elif defined(__linux__)
static ssize_t fixture_getrandom(void* destination, size_t count, unsigned int) {
    fixture_random(destination, count); return static_cast<ssize_t>(count);
}
#define getrandom fixture_getrandom
#else
#error The deterministic oracle supports the native arc4random_buf and getrandom platforms.
#endif
#include "pvac_serialize.hpp"
#include "pvac/ops/recrypt_public.hpp"
#undef arc4random_buf
#undef getrandom
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace pvac;
using namespace pvac::bp;
static Scalar integer(uint64_t value) { return Scalar{{value,0,0,0}}; }
static std::vector<uint8_t> unhex(const std::string& text) {
    std::vector<uint8_t> result(text.size()/2);
    for(size_t i=0;i<result.size();i++) result[i]=std::stoul(text.substr(2*i,2),nullptr,16);
    return result;
}
static Scalar read_scalar() {
    std::string text;std::cin>>text;auto bytes=unhex(text);return sc_from_bytes(bytes.data());
}
static std::string hex(const uint8_t* bytes, size_t count) {
    std::ostringstream out;out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<count;i++) out<<std::setw(2)<<unsigned(bytes[i]);return out.str();
}
static std::string hex(const Scalar& scalar) {uint8_t bytes[32];sc_tobytes(bytes,scalar);return hex(bytes,32);}
static void reset_entropy(uint64_t seed) {entropy_state=seed;entropy_word=0;entropy_available=0;consumed=0;calls=0;}
static std::string system_hash(const R1CSProver& prover) {
    pvac_ser::Writer encoded;encoded.u64(prover.num_gates());encoded.u64(prover.num_committed());encoded.u64(prover.num_constraints());
    for(const auto& constraint:prover.get_constraints()) {
        encoded.u64(constraint.lc.terms.size());
        for(const auto& term:constraint.lc.terms) {encoded.u8(static_cast<uint8_t>(term.first.type));encoded.u64(term.first.index);encoded.scalar(term.second);}
    }
    Sha256 hash;hash.init();hash.update(encoded.buf.data(),encoded.buf.size());uint8_t digest[32];hash.finish(digest);return hex(digest,32);
}
int main(){
 int profile,operation,variant,slots;size_t output_layers,edges_per_layer;uint64_t value;double noise;
 while(std::cin>>profile>>operation>>variant>>slots>>output_layers>>edges_per_layer>>value>>noise){
  try {
   Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=noise;
   uint8_t key_seed[32],seed[32];for(int i=0;i<32;i++){key_seed[i]=i;seed[i]=31-i;}PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,key_seed);set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile));
   std::vector<uint64_t> values;for(int i=0;i<slots;i++)values.push_back(value+i);Cipher input;
   if(variant!=3)input=enc_values_seeded(pk,sk,values,seed);
   if(variant==1)input=ct_square_seeded(pk,input,seed,4,true);
   if(variant==2)input=ct_add(pk,input,input);
   Cipher output;RecryptPublicAudit audit;
   if(operation==0){auto key=make_recrypt_key_seeded(pk,sk,input,output_layers,seed);audit=audit_recrypt_public_key(input,key);output=ct_recrypt_apply_seeded(pk,key,input,seed,edges_per_layer);}
   else {EvalKey key;key.enc_one=enc_value_seeded(pk,sk,1,seed);for(size_t i=0;i<output_layers;i++){seed[0]=i;key.zero_pool.push_back(enc_zero_seeded(pk,sk,seed));}seed[0]=31;output=ct_recrypt_seeded(pk,key,input,seed);}
   auto bytes=pvac_ser::serialize_cipher(output);auto key=make_public_recrypt_key(2,16,1);auto valid=is_public_recrypt_shape(pk,key,input,output);
   std::cout<<"{\"bytes\":\""<<hex(bytes.data(),bytes.size())<<"\",\"rank\":[";
   for(size_t i=0;i<audit.rank.size();i++){if(i)std::cout<<',';std::cout<<audit.rank[i];}
   std::cout<<"],\"quotient\":[";for(size_t i=0;i<audit.quotient.size();i++){if(i)std::cout<<',';std::cout<<audit.quotient[i];}
   std::cout<<"],\"reusable_public_safe\":"<<(audit.reusable_public_safe?"true":"false")<<",\"public_shape\":"<<(valid?"true":"false")<<",\"needs_balance\":"<<(sigma_needs_balance(pk,input)?"true":"false")<<"}\n";
  }catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
 }
}
