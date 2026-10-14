// Test-only oracle. Inner-product proofs are from the unmodified adopted tree.
#include "pvac/crypto/bulletproofs/r1cs_verifier.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace pvac;
using namespace pvac::bp;
static Scalar sc_from_u64(uint64_t value) { return Scalar{{value,0,0,0}}; }

static std::string hex(const uint8_t* bytes,size_t n) {
    std::ostringstream out;out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<n;i++)out<<std::setw(2)<<unsigned(bytes[i]);
    return out.str();
}
static std::string hex(const Scalar& value) {uint8_t bytes[32];sc_tobytes(bytes,value);return hex(bytes,32);}
static std::vector<Scalar> read_scalars(size_t n) {
    std::vector<Scalar> out;out.reserve(n);
    for(size_t i=0;i<n;i++) {
        std::string text;std::cin>>text;uint8_t bytes[32];
        for(size_t j=0;j<32;j++)bytes[j]=std::stoul(text.substr(2*j,2),nullptr,16);
        out.push_back(sc_from_bytes(bytes));
    }
    return out;
}
static void print_scalars(const std::vector<Scalar>& values) {
    std::cout<<'[';bool first=true;
    for(const auto& value:values) {if(!first)std::cout<<',';first=false;std::cout<<'"'<<hex(value)<<'"';}
    std::cout<<']';
}
static void print_points(const std::vector<RistrettoPoint>& values) {
    std::cout<<'[';bool first=true;
    for(const auto& value:values) {if(!first)std::cout<<',';first=false;std::cout<<'"'<<hex(value.data(),32)<<'"';}
    std::cout<<']';
}
static Transcript transcript(ScalarRule rule,size_t n) {
    Transcript value("pvac.bp.ipp.fixture",rule);value.append_u64("n",n);return value;
}
static void check(ScalarRule rule,size_t initial_n,size_t n,const RistrettoPoint& p,const RistrettoPoint& q,
    const InnerProductProof& proof,const std::vector<Scalar>& y,bool weighted) {
    auto t=transcript(rule,initial_n);
    try {
        bool result=weighted?ipp_verify_with_y(t,p,q,proof,n,y):ipp_verify(t,p,q,proof,n);
        std::cout<<"{\"accepted\":"<<(result?"true":"false");
    } catch(const std::exception& error) {std::cout<<"{\"error\":\""<<error.what()<<'"';}
    std::cout<<",\"after\":\""<<hex(t.challenge_scalar("after"))<<"\"}";
}
int main() {
    std::string mode;int rule_id;size_t n;
    while(std::cin>>mode>>rule_id>>n) {
        ScalarRule rule=rule_id?ScalarRule::Wide:ScalarRule::Prior;ScalarOps ops(rule);
        if(mode=="prove") {
            int variant;std::cin>>variant;
            auto a=read_scalars(n),b=read_scalars(n);
            auto g=generators().G_vec(n),h=generators().H_vec(n);
            std::vector<Scalar> y(n,sc_from_u64(1));
            for(size_t i=0;i<n;i++) {
                if(variant==1) {y[i]=sc_from_u64(i+2);h[i]=rist_scalarmul(h[i],y[i]);}
                if(variant==2) {g[i]=rist_identity();h[i]=rist_identity();}
            }
            auto q=hash_to_ristretto_point("pvac.bp.ipp.fixture.Q",7);
            auto scalars=a;scalars.insert(scalars.end(),b.begin(),b.end());scalars.push_back(inner_product(a,b,ops));
            auto points=g;points.insert(points.end(),h.begin(),h.end());points.push_back(q);
            auto p=multi_scalar_mul(scalars,points);
            auto t=transcript(rule,n);
            auto proof=ipp_prove(t,q,a,b,g,h);
            std::cout<<"{\"g\":";print_points(g);std::cout<<",\"h\":";print_points(h);
            std::cout<<",\"y\":";print_scalars(y);
            std::cout<<",\"p\":\""<<hex(p.data(),32)<<"\",\"q\":\""<<hex(q.data(),32)<<"\",\"l\":";print_points(proof.L);
            std::cout<<",\"r\":";print_points(proof.R);
            std::cout<<",\"a\":\""<<hex(proof.a)<<"\",\"b\":\""<<hex(proof.b)
                <<"\",\"after\":\""<<hex(t.challenge_scalar("after"))<<"\",\"verify\":[";
            for(int mutation=0;mutation<12;mutation++) {
                auto changed=proof;auto changed_p=p,changed_q=q;auto changed_y=y;size_t changed_n=n;
                if(mutation==1)changed_n=0;
                if(mutation==2)changed_n=n+1;
                if(mutation==3)changed.R.push_back(rist_identity());
                if(mutation==4)changed_p.fill(255);
                if(mutation==5)changed_q.fill(255);
                if(mutation==6) {if(changed.L.empty())changed.L.push_back({});changed.L[0].fill(255);}
                if(mutation==7) {if(changed.R.empty())changed.R.push_back({});changed.R[0].fill(255);}
                if(mutation==8)changed.a=sc_add(changed.a,sc_from_u64(1));
                if(mutation==9)changed.b=Scalar{{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX}};
                if(mutation==10)changed_y.pop_back();
                if(mutation==11)changed_y.assign(n,sc_zero());
                if(mutation)std::cout<<',';
                std::cout<<"{\"mutation\":"<<mutation<<",\"raw\":";
                check(rule,n,changed_n,changed_p,changed_q,changed,changed_y,false);
                std::cout<<",\"weighted\":";
                check(rule,n,changed_n,changed_p,changed_q,changed,changed_y,true);
                std::cout<<'}';
            }
            std::cout<<"]}\n";
        } else {
            auto values=read_scalars(n);
            if(mode=="inner") {auto right=read_scalars(n);std::cout<<"{\"scalar\":\""<<hex(inner_product(values,right,ops))<<"\"}\n";}
            else {std::cout<<"{\"scalars\":";print_scalars(mode=="batch"?batch_sc_inv(values,ops):ipp_verification_scalars(values,ops));std::cout<<"}\n";}
        }
    }
}
