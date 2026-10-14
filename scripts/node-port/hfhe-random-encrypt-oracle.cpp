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
int main() {
 int profile,depth,operation,slots;uint64_t value,entropy_seed;double noise;
 while(std::cin>>profile>>depth>>operation>>slots>>value>>entropy_seed>>noise){
  try {
   Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=noise;
   uint8_t key_seed[32];for(int i=0;i<32;i++)key_seed[i]=i;PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,key_seed);set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile));
   std::vector<Fp> values;for(int i=0;i<slots;i++)values.push_back(fp_from_u64(value+i));
   reset_entropy(entropy_seed);
   uint8_t seed[32];for(int i=0;i<32;i++)seed[i]=31-i;
   auto cipher=operation==0?enc_fp_depth(pk,sk,values,depth):operation==1?enc_fp_wrapped_depth(pk,sk,values,depth):operation==2?enc(pk,sk,values):operation==3?enc_nat_fp_seeded(pk,sk,values,seed):enc_ru_fp_seeded(pk,sk,values,seed);
   auto bytes=pvac_ser::serialize_cipher(cipher);
   std::cout<<"{\"bytes\":\""<<hex(bytes.data(),bytes.size())<<"\",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";
  }catch(const std::exception& e){std::cout<<"{\"error\":\""<<e.what()<<"\",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";}
 }
}
