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
int main() {
    int profile_id,rule_id,variant,make_proof;uint64_t value,amount,entropy_seed;std::string operation;
    while(std::cin>>profile_id>>rule_id>>operation>>variant>>value>>amount>>make_proof>>entropy_seed) {
        try {
            auto rule=rule_id?ScalarRule::Wide:ScalarRule::Prior;
            Params params;params.B=126;params.m_bits=65;params.n_bits=17;params.h_col_wt=13;params.x_col_wt=7;params.err_wt=2;params.lpn_n=65;params.lpn_t=127;params.noise_entropy_bits=0;
            uint8_t key_seed[32],seed[32];for(int i=0;i<32;i++){key_seed[i]=i;seed[i]=31-i;}
            PubKey pk;SecKey sk;keygen_from_seed(params,pk,sk,key_seed);
            set_circuit_prf_profile(pk,sk,static_cast<CircuitPrfProfile>(profile_id));
            auto rng=make_seeded_rng(seed);
            Cipher cipher=enc_fp_depth_seeded(pk,sk,std::vector<Fp>{fp_from_u64(value)},0,rng);
            if(variant==1)cipher=enc_value_seeded(pk,sk,value,seed);
            if(variant==2)cipher=ct_square_seeded(pk,cipher,seed,4,true);
            if(variant==3)cipher=ct_sub(pk,cipher,cipher);
            auto coefficients=compute_layer_coeffs(pk,cipher);auto bases=base_layer_indices(cipher);
            std::vector<std::vector<Fp>> masks(cipher.L.size()),inverse(cipher.L.size());std::vector<uint8_t> status(cipher.L.size(),0);
            for(size_t layer=0;layer<cipher.L.size();layer++)layer_R_cached(pk,sk,cipher,layer,status,masks);
            for(size_t layer=0;layer<cipher.L.size();layer++)for(auto mask:masks[layer])inverse[layer].push_back(fp_inv(mask));
            detail::AmountBinding binding;binding.amount=amount;binding.blinding=integer(19);if(operation=="range")binding.range_bits=64;
            bool legacy=operation=="legacy",bound=operation!="zero"&&!legacy,migration=operation=="migration";
            R1CSProver prover(rule);
            if(legacy)detail::build_circuit(prover,cipher,coefficients,bases,&inverse,&sk);
            else detail::build_key_bound_circuit(prover,pk,&sk,cipher,coefficients,bases,&masks,&inverse,bound?&binding:nullptr,migration,true);
            auto verifier=R1CSProver::verification(rule);detail::AmountBinding dummy;if(operation=="range")dummy.range_bits=64;
            if(legacy)detail::build_circuit(verifier,cipher,coefficients,bases,nullptr,nullptr);
            else detail::build_key_bound_circuit(verifier,pk,nullptr,cipher,coefficients,bases,nullptr,nullptr,bound?&dummy:nullptr,migration,true);
            const char* domain=operation=="zero"?"pvac.verify_zero.key_bound":operation=="range"?"pvac.verify_zero_bound_range.key_bound":migration?"pvac.historical_migration.bound":"pvac.verify_zero_bound.key_bound";
            const char* kind=operation=="zero"?"zero":operation=="range"?"bound_range":migration?"historical_migration":"bound";
            auto commitment=pedersen_commit(integer(amount),binding.blinding);
            auto transcript=[&](){Transcript t(domain,rule);t.append_u64("nL",cipher.L.size());t.append_u64("S",cipher.slots);t.append_u64("nB",bases.size());if(!legacy)detail::append_key_bound_transcript_context(t,pk,cipher,kind,bound?&commitment:nullptr);return t;};
            auto t=transcript();auto initial=t;
            std::cout<<"{\"gates\":"<<prover.num_gates()<<",\"committed\":"<<prover.num_committed()<<",\"constraints\":"<<prover.num_constraints()<<",\"system_sha256\":\""<<system_hash(prover)<<"\",\"verification_sha256\":\""<<system_hash(verifier)<<"\",\"initial\":\""<<hex(initial.challenge_scalar("after"))<<"\",\"amount_terms\":"<<(detail::amount_terms_present(cipher,coefficients)?"true":"false");
            reset_entropy(entropy_seed);
            if(make_proof) {
                auto limits=(operation=="key_switch"||migration)?R1CSLimitProfile::KeySwitchRefresh:R1CSLimitProfile::Default;
                auto proof=prover.prove(t,limits);pvac_ser::Writer bytes;pvac_ser::write_r1cs_proof_raw(bytes,proof);
                std::cout<<",\"proof\":\""<<hex(bytes.buf.data(),bytes.buf.size())<<"\",\"after\":\""<<hex(t.challenge_scalar("after"))<<'"';
                ConstraintSystem system;system.num_gates=verifier.num_gates();system.num_committed=verifier.num_committed();system.constraints=std::move(verifier).get_constraints();
                auto checked=transcript();bool accepted=r1cs_verify(checked,system,proof,limits);
                std::cout<<",\"accepted\":"<<(accepted?"true":"false")<<",\"verify_after\":\""<<hex(checked.challenge_scalar("after"))<<'"';
                if(!legacy) {
                    ZeroProof zero;zero.proof=proof;zero.is_bound=bound;
                    bool wrapped=operation=="zero"?verify_zero(pk,cipher,zero,rule):operation=="range"?verify_zero_bound_range(pk,cipher,zero,commitment,rule):migration?verify_zero_bound_historical_migration(pk,cipher,zero,commitment,rule):operation=="key_switch"?verify_zero_bound_key_switch(pk,cipher,zero,commitment,rule):verify_zero_bound(pk,cipher,zero,commitment,rule);
                    std::cout<<",\"wrapped_accepted\":"<<(wrapped?"true":"false");
                }
            }
            std::cout<<",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";
        }catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
    }
}
