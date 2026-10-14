// Test-only entropy tape adapter; adopted PVAC headers remain unmodified.
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#if defined(__linux__)
#include <sys/random.h>
#endif
static std::vector<unsigned char> entropy_tape;
static size_t consumed = 0, calls = 0;
static void fixture_random(void* destination, size_t count) {
    ++calls;
    if (count > entropy_tape.size() - consumed) throw std::runtime_error("fixture entropy exhausted");
    std::memcpy(destination, entropy_tape.data() + consumed, count); consumed += count;
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
static void variable(pvac_ser::Writer& bytes,Variable variable) {
    bytes.u8(static_cast<uint8_t>(variable.type));bytes.u64(variable.index);
}
int main() {
    std::string kind;int rule_id,canonical,make_proof;size_t bits;
    while(std::cin>>kind>>rule_id>>canonical>>bits>>make_proof) {
        auto a=read_scalar(),b=read_scalar();std::string tape;std::cin>>tape;
        entropy_tape=unhex(tape);consumed=0;calls=0;
        auto rule=rule_id?ScalarRule::Wide:ScalarRule::Prior;
        R1CSProver prover(rule);ScalarOps ops(rule);
        auto av=prover.commit(a,integer(11));auto bv=prover.commit(b,integer(13));
        std::vector<std::pair<Variable,Scalar>> outputs;
        if(kind=="range")range_check(prover,av,a,bits);
        else if(kind=="alias")reject_mersenne_modulus_alias(prover,av,a);
        else if(kind=="decompose") {
            auto result=fp127_decompose(prover,av,a,canonical);
            outputs={{result.x0_var,result.x0_val},{result.x1_var,result.x1_val}};
        } else if(kind=="mul" || kind=="cube" || kind=="fifth") {
            auto result=kind=="mul"?fp_mul_gadget(prover,av,a,bv,b,canonical):
                kind=="cube"?fp_cube_gadget(prover,av,a,canonical):fp_fifth_gadget(prover,av,a,canonical);
            outputs={{result.var,result.val}};
        } else if(kind=="bind") {
            auto result=bind_pc_value(prover,av,fp_from_words(b.v[0],b.v[1]),canonical);
            outputs={{result.x_var,result.x_val},{result.limbs.x0_var,result.limbs.x0_val},{result.limbs.x1_var,result.limbs.x1_val}};
        } else if(kind=="fold") {
            auto limbs=fp127_decompose(prover,av,a,canonical);
            auto result=fp_mul_const_var_folded(fp_from_words(b.v[0],b.v[1]),limbs,ops);
            prover.constrain(result.lc);outputs={{av,result.val}};
        } else return 2;
        pvac_ser::Writer encoded;
        encoded.u64(prover.num_gates());encoded.u64(prover.num_committed());encoded.u64(prover.num_constraints());
        for(const auto& constraint:prover.get_constraints()) {
            encoded.u64(constraint.lc.terms.size());
            for(const auto& term:constraint.lc.terms) {variable(encoded,term.first);encoded.scalar(term.second);}
        }
        encoded.u64(outputs.size());for(const auto& result:outputs){variable(encoded,result.first);encoded.scalar(result.second);}
        Sha256 hash;hash.init();hash.update(encoded.buf.data(),encoded.buf.size());uint8_t digest[32];hash.finish(digest);
        std::cout<<"{\"gates\":"<<prover.num_gates()<<",\"constraints\":"<<prover.num_constraints()
            <<",\"system_sha256\":\""<<hex(digest,32)<<'"';
        if(make_proof) {
            Transcript t("pvac.bp.gadgets.fixture",rule);t.append_message("kind",reinterpret_cast<const uint8_t*>(kind.data()),kind.size());
            auto proof=prover.prove(t);pvac_ser::Writer bytes;pvac_ser::write_r1cs_proof_raw(bytes,proof);
            std::cout<<",\"proof\":\""<<hex(bytes.buf.data(),bytes.buf.size())<<"\",\"after\":\""<<hex(t.challenge_scalar("after"))<<'"';
            ConstraintSystem system;system.num_gates=prover.num_gates();system.num_committed=prover.num_committed();system.constraints=prover.get_constraints();
            Transcript checked("pvac.bp.gadgets.fixture",rule);checked.append_message("kind",reinterpret_cast<const uint8_t*>(kind.data()),kind.size());
            bool accepted=r1cs_verify(checked,system,proof);
            std::cout<<",\"accepted\":"<<(accepted?"true":"false")<<",\"verify_after\":\""<<hex(checked.challenge_scalar("after"))<<'"';
        }
        std::cout<<",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";
    }
}
