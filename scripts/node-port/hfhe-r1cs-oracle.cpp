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
static Transcript transcript(ScalarRule rule, int variant, bool different=false) {
    Transcript out(different?"pvac.bp.r1cs.wrong":"pvac.bp.r1cs.fixture",rule);
    out.append_u64("variant",variant);return out;
}
static R1CSProver build(ScalarRule rule,int variant,const std::vector<std::pair<Scalar,Scalar>>& commits,
        const std::vector<std::pair<Scalar,Scalar>>& gates,bool values) {
    auto out=values?R1CSProver(rule):R1CSProver::verification(rule);ScalarOps ops(rule);
    for(const auto& item:commits) {
        auto var=out.commit(item.first,item.second);
        if(variant!=3) out.constrain(LinearCombination(var)-item.first);
    }
    for(size_t i=0;i<gates.size();i++) {
        auto left=gates[i].first,right=gates[i].second;
        std::tuple<Variable,Variable,Variable> vars;
        if(variant==1) {
            auto lc_left=LinearCombination(Variable::one(),left);
            if(!commits.empty()) {lc_left+=LinearCombination(Variable::committed(i%commits.size()));left=sc_add(left,commits[i%commits.size()].first);}
            vars=out.multiply(lc_left,LinearCombination(Variable::one(),right));
        } else vars=out.allocate(left,right);
        if(variant==0 || variant==1 || variant==2) {
            out.constrain(LinearCombination(std::get<0>(vars))-left);
            out.constrain(LinearCombination(std::get<1>(vars))-right);
            auto expected=ops.mul(left,right);if(variant==2)expected=sc_add(expected,integer(1));
            out.constrain(LinearCombination(std::get<2>(vars))-expected);
        }
        if(variant==5) {
            out.constrain(LinearCombination());
            auto duplicate=LinearCombination(std::get<0>(vars));duplicate-=LinearCombination(std::get<0>(vars));
            duplicate+=LinearCombination(Variable::one(),sc_zero());out.constrain(duplicate);
        }
    }
    if(variant==4) {
        out.constrain(LinearCombination(Variable::mult_out(gates.size())));
        out.constrain(LinearCombination({VarType::ONE,1},integer(1)));
        out.constrain(LinearCombination({static_cast<VarType>(5),0},integer(1)));
        out.constrain(LinearCombination(Variable::committed(commits.size())));
    }
    return out;
}
static void check(ScalarRule rule,int variant,const ConstraintSystem& original,const R1CSProof& proof,int mutation) {
    auto system=original;auto changed=proof;
    if(mutation==1)system.num_gates=R1CS_MAX_GATES+1;
    if(mutation==2)system.num_committed=R1CS_MAX_COMMITTED+1;
    if(mutation==3)changed.V.push_back(rist_identity());
    if(mutation==4)changed.A_I1.fill(255);
    if(mutation==5)changed.T_6.fill(255);
    if(mutation==6){changed.ipp.L.push_back({});changed.ipp.R.push_back({});changed.ipp.L.back().fill(255);}
    if(mutation==7)changed.t_x=sc_add(changed.t_x,integer(1));
    if(mutation==8)changed.t_x_blinding=Scalar{{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX}};
    if(mutation==9)changed.e_blinding=sc_add(changed.e_blinding,integer(1));
    if(mutation==10)changed.ipp.a=sc_add(changed.ipp.a,integer(1));
    if(mutation==11)changed.ipp.R.push_back(rist_identity());
    if(mutation==12)system.constraints.clear();
    if(mutation==13)system.constraints.push_back({LinearCombination(Variable::one())});
    if(mutation==14)system.constraints.push_back({LinearCombination(Variable::mult_left(system.num_gates))});
    if(mutation==15){if(changed.V.empty())changed.V.push_back(pedersen_B());else changed.V[0]=pedersen_B();}
    if(mutation==18)system.constraints.push_back({LinearCombination(Variable::one(),Scalar{{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX}})});
    if(mutation==19){changed.ipp.L.push_back(rist_identity());changed.ipp.R.push_back(rist_identity());}
    if(mutation==20)system.num_gates+=1;
    if(mutation==21)changed.ipp.b=Scalar{{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX}};
    auto t=transcript(rule,variant,mutation==16);
    bool accepted=r1cs_verify(t,system,changed,mutation==17?R1CSLimitProfile::KeySwitchRefresh:R1CSLimitProfile::Default);
    std::cout<<"{\"accepted\":"<<(accepted?"true":"false")<<",\"after\":\""<<hex(t.challenge_scalar("after"))<<"\"}";
}
int main() {
    int rule_id,variant,error_case;size_t n,m;
    while(std::cin>>rule_id>>variant>>error_case>>n>>m) {
        ScalarRule rule=rule_id?ScalarRule::Wide:ScalarRule::Prior;
        std::vector<std::pair<Scalar,Scalar>> commits,gates;
        for(size_t i=0;i<m;i++){auto first=read_scalar();auto second=read_scalar();commits.emplace_back(first,second);}
        for(size_t i=0;i<n;i++){auto first=read_scalar();auto second=read_scalar();gates.emplace_back(first,second);}
        std::string tape;std::cin>>tape;entropy_tape=unhex(tape);consumed=0;calls=0;
        auto prover=build(rule,variant,commits,gates,error_case!=1);
        if(error_case==3)for(size_t i=0;i<=R1CS_MAX_COMMITTED;i++)prover.commit(sc_zero(),sc_zero());
        auto t=transcript(error_case==2?(rule_id?ScalarRule::Prior:ScalarRule::Wide):rule,variant);
        try {
            auto proof=prover.prove(t);
            pvac_ser::Writer bytes;pvac_ser::write_r1cs_proof_raw(bytes,proof);
            std::cout<<"{\"proof\":\""<<hex(bytes.buf.data(),bytes.buf.size())<<"\",\"verify\":[";
            ConstraintSystem system;system.num_gates=prover.num_gates();system.num_committed=prover.num_committed();system.constraints=prover.get_constraints();
            for(int mutation=0;mutation<22;mutation++){if(mutation)std::cout<<',';check(rule,variant,system,proof,mutation);}
            std::cout<<']';
        } catch(const std::exception& error) {std::cout<<"{\"error\":\""<<error.what()<<'"';}
        std::cout<<",\"after\":\""<<hex(t.challenge_scalar("after"))<<"\",\"consumed\":"<<consumed<<",\"calls\":"<<calls<<"}\n";
    }
}
