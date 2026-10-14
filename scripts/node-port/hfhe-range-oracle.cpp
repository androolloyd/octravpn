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
static std::string cipher_hash(const Cipher& cipher){auto bytes=pvac_ser::serialize_cipher(cipher);Sha256 h;h.init();h.update(bytes.data(),bytes.size());uint8_t digest[32];h.finish(digest);return hex(digest,32);}
int main(){
 int profile,rule_id,variant,prove;uint64_t value,entropy_seed;
 while(std::cin>>profile>>rule_id>>variant>>prove>>value>>entropy_seed){
  try{
   auto rule=rule_id?ScalarRule::Wide:ScalarRule::Prior;
   Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=0;
   uint8_t key_seed[32];for(int i=0;i<32;i++)key_seed[i]=i;PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,key_seed);set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile));
   std::vector<Cipher> bits;std::vector<detail::BitPrepData> data(RANGE_BITS);
   for(size_t i=0;i<RANGE_BITS;i++){
    uint8_t seed[32];for(size_t k=0;k<32;k++)seed[k]=(i*17+k*11+7)&255;auto rng=make_seeded_rng(seed);
    bits.push_back(variant?enc_value_seeded(pk,sk,(value>>i)&1,seed):enc_fp_depth_seeded(pk,sk,std::vector<Fp>{fp_from_u64((value>>i)&1)},0,rng));
    detail::prepare_bit(pk,sk,bits.back(),i,data[i]);
   }
   uint8_t seed[32];for(int i=0;i<32;i++)seed[i]=31-i;auto rng=make_seeded_rng(seed);auto cipher=enc_fp_depth_seeded(pk,sk,std::vector<Fp>{fp_from_u64(value)},0,rng);
   auto diff=detail::compute_lc_diff(pk,bits,cipher);detail::BitPrepData lc;detail::prepare_lc(pk,sk,diff,lc);
   R1CSProver prover(rule);for(auto& item:data)detail::build_circuit(prover,item.ct_check,item.A,item.bases,&item.rinv,&sk);detail::build_circuit(prover,lc.ct_check,lc.A,lc.bases,&lc.rinv,&sk);
   auto state=[&](){Transcript t("pvac.range_proof.aggregated",rule);detail::append_transcript_params(t,data,lc);return t;};auto initial=state();
   std::cout<<"{\"gates\":"<<prover.num_gates()<<",\"committed\":"<<prover.num_committed()<<",\"constraints\":"<<prover.num_constraints()<<",\"system_sha256\":\""<<system_hash(prover)<<"\",\"initial\":\""<<hex(initial.challenge_scalar("after"))<<"\",\"checks\":[";
   for(size_t i=0;i<RANGE_BITS;i++){if(i)std::cout<<',';std::cout<<'"'<<cipher_hash(data[i].ct_check)<<'"';}
   std::cout<<"],\"difference\":\""<<cipher_hash(diff)<<"\",\"lc_layers\":"<<diff.L.size()<<",\"lc_bases\":"<<lc.bases.size();
   try{make_zero_proof(pk,sk,diff,rule);std::cout<<",\"lc_error\":null";}catch(const std::exception& error){std::cout<<",\"lc_error\":\""<<error.what()<<'"';}
   AggregatedRangeProof aggregated;aggregated.ct_bit=bits;std::cout<<",\"aggregated_accepted\":"<<(verify_aggregated_range(pk,cipher,aggregated)?"true":"false");
   RangeProof ordinary;ordinary.ct_bit=bits;ordinary.bit_proofs.resize(RANGE_BITS);std::cout<<",\"empty_proofs_accepted\":"<<(verify_range(pk,cipher,ordinary,rule)?"true":"false");
   reset_entropy(entropy_seed);
   if(prove){auto t=state();auto proof=prover.prove(t);pvac_ser::Writer bytes;pvac_ser::write_r1cs_proof_raw(bytes,proof);std::cout<<",\"proof\":\""<<hex(bytes.buf.data(),bytes.buf.size())<<"\",\"after\":\""<<hex(t.challenge_scalar("after"))<<'"';}
   std::cout<<",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";
  }catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
 }
}
