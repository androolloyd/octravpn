// Test-only noise-budget driver. Native behavior is compiler/architecture scoped.
#include "pvac_serialize.hpp"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>

static std::string bits(double value) {
    uint64_t raw;std::memcpy(&raw,&value,8);
    std::ostringstream out;out<<std::hex<<std::setw(16)<<std::setfill('0')<<raw;return out.str();
}
static double from_bits(const std::string& input) {
    uint64_t raw=std::stoull(input,nullptr,16);double value;std::memcpy(&value,&raw,8);return value;
}
int main() {
    pvac::Params p;int depth;std::string entropy,slope,fraction;
    while(std::cin>>p.B>>entropy>>slope>>depth>>fraction) {
        p.noise_entropy_bits=from_bits(entropy);p.depth_slope_bits=from_bits(slope);p.tuple2_fraction=from_bits(fraction);
        double d=std::max(0,depth);
        double cap=p.noise_entropy_bits+p.depth_slope_bits*d;
        volatile double product=p.depth_slope_bits*d;
        double split=p.noise_entropy_bits+product;
        double fused=std::fma(p.depth_slope_bits,d,p.noise_entropy_bits);
        double q2=std::floor(cap*p.tuple2_fraction/std::max(1e-6,2.0*std::log2(static_cast<double>(p.B))));
        double q3=std::floor(cap*(1.0-p.tuple2_fraction)/std::max(1e-6,3.0*std::log2(static_cast<double>(p.B))));
        if(!std::isfinite(q2)||!std::isfinite(q3)||q2<INT32_MIN||q2>INT32_MAX||q3<INT32_MIN||q3>INT32_MAX||
            std::max(0.0,q2)+std::max(0.0,q3)>INT32_MAX) {
            std::cerr<<"budget fixture outside defined native int range\n";return 2;
        }
        auto budget=pvac::entropy::Budget::compute(p,depth);
        std::cout<<"{\"n2\":"<<budget.n2<<",\"n3\":"<<budget.n3
            <<",\"cap_bits\":\""<<bits(cap)<<"\",\"split_cap_bits\":\""<<bits(split)
            <<"\",\"fused_cap_bits\":\""<<bits(fused)<<"\"}\n";
    }
}
