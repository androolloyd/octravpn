// Test-only transcript, generator and group oracle from pristine PVAC headers.
#include "pvac_serialize.hpp"
#include "pvac/crypto/bulletproofs/inner_product.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const uint8_t* bytes,size_t size) {
    std::ostringstream out;out<<std::hex<<std::setfill('0');
    for(size_t i=0;i<size;++i)out<<std::setw(2)<<unsigned(bytes[i]);return out.str();
}
static std::vector<uint8_t> unhex(const std::string& text) {
    std::vector<uint8_t> out;if(text=="-")return out;
    for(size_t i=0;i<text.size();i+=2)out.push_back(std::stoul(text.substr(i,2),nullptr,16));return out;
}
static std::string label(const std::string& text) {
    auto raw=unhex(text);return std::string(raw.begin(),raw.end());
}
static pvac::RistrettoPoint point(const std::string& text) {
    auto raw=unhex(text);pvac::RistrettoPoint p{};std::copy(raw.begin(),raw.end(),p.begin());return p;
}
static pvac::Scalar scalar(const std::string& text) {
    auto raw=unhex(text);return pvac::sc_from_bytes(raw.data());
}
static std::string scalar_hex(const pvac::Scalar& value) {
    uint8_t bytes[32];pvac::sc_tobytes(bytes,value);return hex(bytes,32);
}
template<class F> static void point_result(const char* name,F fn) {
    try { auto p=fn();std::cout<<'"'<<name<<"\":\""<<hex(p.data(),p.size())<<'"'; }
    catch(const std::exception& error){std::cout<<'"'<<name<<"_error\":\""<<error.what()<<'"';}
}
int main() {
    std::string mode;
    while(std::cin>>mode) {
        try {
            if(mode=="transcript") {
                std::string domain;unsigned rule;size_t count;std::cin>>domain>>rule>>count;
                auto dom=label(domain);pvac::bp::Transcript t(dom.c_str(),static_cast<pvac::ScalarRule>(rule));
                std::vector<pvac::Scalar> challenges;
                for(size_t i=0;i<count;++i) {
                    std::string op,name,data;std::cin>>op>>name;auto tag=label(name);
                    if(op=="c")challenges.push_back(t.challenge_scalar(tag.c_str()));
                    else if(op=="u") {uint64_t value;std::cin>>value;t.append_u64(tag.c_str(),value);}
                    else {std::cin>>data;
                        if(op=="m") {auto raw=unhex(data);t.append_message(tag.c_str(),raw.data(),raw.size());}
                        else if(op=="p")t.append_point(tag.c_str(),point(data));
                        else t.append_scalar(tag.c_str(),scalar(data));
                    }
                }
                std::cout<<"{\"challenges\":[";
                for(size_t i=0;i<challenges.size();++i){if(i)std::cout<<',';std::cout<<'"'<<scalar_hex(challenges[i])<<'"';}
                std::cout<<"]}\n";
            } else if(mode=="hash") {
                std::string domain;uint64_t index;std::cin>>domain>>index;auto dom=label(domain);
                auto p=pvac::bp::hash_to_ristretto_point(dom.c_str(),index);
                std::cout<<"{\"point\":\""<<hex(p.data(),32)<<"\"}\n";
            } else if(mode=="table") {
                std::string op;size_t n;std::cin>>op>>n;auto& table=pvac::bp::generators();
                if(op=="g"||op=="h") {
                    auto p=op=="g" ? table.G(n):table.H(n);std::cout<<"{\"point\":\""<<hex(p.data(),32)<<"\"}\n";
                } else if(op=="precompute") {table.precompute(n);std::cout<<"{\"ok\":true}\n";}
                else {
                    auto points=op=="g_vec"?table.G_vec(n):table.H_vec(n);std::cout<<"{\"points\":[";
                    for(size_t i=0;i<points.size();++i){if(i)std::cout<<',';std::cout<<'"'<<hex(points[i].data(),32)<<'"';}
                    std::cout<<"]}\n";
                }
            } else if(mode=="size") {
                std::string op;size_t n;std::cin>>op>>n;
                auto result=op=="next"?pvac::bp::next_power_of_2(n):pvac::bp::log2_size(n);
                std::cout<<"{\"value\":"<<result<<"}\n";
            } else if(mode=="group") {
                std::string ah,bh,sh,rh;std::cin>>ah>>bh>>sh>>rh;
                auto a=point(ah),b=point(bh);auto s=scalar(sh),r=scalar(rh);pvac::ExtPoint decoded;
                std::cout<<"{\"valid\":"<<(pvac::rist_decode(decoded,a)?"true":"false")<<',';
                point_result("add",[&]{return pvac::rist_add(a,b);});std::cout<<',';
                point_result("sub",[&]{return pvac::rist_sub(a,b);});std::cout<<',';
                point_result("mul",[&]{return pvac::rist_scalarmul(a,s);});std::cout<<',';
                point_result("base",[&]{return pvac::rist_basemul(s);});std::cout<<',';
                point_result("pedersen",[&]{return pvac::pedersen_commit(s,r);});std::cout<<"}\n";
            } else if(mode=="msm") {
                size_t n;std::cin>>n;std::vector<pvac::Scalar> scalars;std::vector<pvac::RistrettoPoint> points;
                for(size_t i=0;i<n;++i){std::string s,p;std::cin>>s>>p;scalars.push_back(scalar(s));points.push_back(point(p));}
                auto p=pvac::bp::multi_scalar_mul(scalars,points);std::cout<<"{\"point\":\""<<hex(p.data(),32)<<"\"}\n";
            }
        } catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
    }
}
