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
int main(){int profile,variant;uint64_t entropy_seed;
 while(std::cin>>profile>>variant>>entropy_seed){reset_entropy(entropy_seed);try{
  Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=0;
  uint8_t key_seed[32],seed[32];for(int i=0;i<32;i++){key_seed[i]=i;seed[i]=31-i;}PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,key_seed);set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile));
  auto rng=make_seeded_rng(seed);Cipher input=variant==0?enc_fp_depth_seeded(pk,sk,std::vector<Fp>{fp_from_u64(0)},0,rng):enc_value_seeded(pk,sk,0,seed);Cipher output=input;
  auto key=make_public_recrypt_key(4,128,1);key.require_smaller=false;PublicRecryptProof proof;
  if(variant==2)output=ct_add_const(pk,output,uint64_t(1));
  reset_entropy(entropy_seed);
  if(variant==3){key.require_smaller=true;auto bundle=make_public_recrypt_bundle_seeded(pk,sk,key,input,seed,1,4);output=bundle.output;proof=bundle.proof;}
  else proof=prove_public_recrypt(pk,sk,input,output);
  auto accepted=verify_public_recrypt(pk,key,input,output,proof);auto bytes=pvac_ser::serialize_cipher(output);pvac_ser::Writer encoded;pvac_ser::write_zero_proof_raw(encoded,proof.equality);
  auto changed=proof;changed.equality.is_bound=true;bool bound=verify_public_recrypt(pk,key,input,output,changed);changed=proof;changed.output_layers++;bool layers=verify_public_recrypt(pk,key,input,output,changed);changed=proof;changed.output_edges++;bool edges=verify_public_recrypt(pk,key,input,output,changed);
  std::cout<<"{\"cipher\":\""<<hex(bytes.data(),bytes.size())<<"\",\"proof\":\""<<hex(encoded.buf.data(),encoded.buf.size())<<"\",\"output_layers\":"<<proof.output_layers<<",\"output_edges\":"<<proof.output_edges<<",\"accepted\":"<<accepted<<",\"mutations\":["<<bound<<','<<layers<<','<<edges<<"],\"calls\":"<<calls<<",\"consumed\":"<<consumed<<"}\n";
 }catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\",\"calls\":"<<calls<<",\"consumed\":"<<consumed<<"}\n";}}
}
