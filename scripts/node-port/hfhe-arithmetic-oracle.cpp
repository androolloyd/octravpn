// Test-only oracle. Cipher arithmetic is unmodified pinned upstream code.
#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out; out << std::hex << std::setfill('0');
    for(auto byte:bytes) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}
static std::vector<uint8_t> unhex(const std::string& value) {
    std::vector<uint8_t> bytes;
    if(value=="-") return bytes;
    for(size_t i=0;i<value.size();i+=2)bytes.push_back(std::stoul(value.substr(i,2),nullptr,16));
    return bytes;
}
int main() {
    pvac::Params params; params.B=7; params.m_bits=65; params.n_bits=17;
    params.h_col_wt=13; params.x_col_wt=7; params.err_wt=2; params.lpn_n=65; params.lpn_t=129;
    uint8_t seed[32]={}; pvac::PubKey public_key; pvac::SecKey secret_key;
    pvac::keygen_from_seed(params,public_key,secret_key,seed);
    std::string op;
    while(std::cin >> op) {
        uint64_t budget,lo,hi,scalar; bool math; std::string left,right;
        std::cin >> budget >> math >> lo >> hi >> scalar >> left >> right;
        public_key.prm.edge_budget=budget;
        try {
            auto bytes=unhex(left);
            auto a=pvac_ser::deserialize_cipher(bytes.data(),bytes.size());
            pvac::Cipher result;
            auto value=pvac::fp_from_words(lo,hi);
            if(op=="add" || op=="sub") {
                bytes=unhex(right);
                auto b=pvac_ser::deserialize_cipher(bytes.data(),bytes.size());
                result=op=="add" ? pvac::ct_add(public_key,a,b) : pvac::ct_sub(public_key,a,b);
            } else if(op=="scale")result=pvac::ct_scale(public_key,a,value);
            else if(op=="scale_i64")result=pvac::ct_mul_const(public_key,a,static_cast<int64_t>(scalar));
            else if(op=="scale_u64")result=pvac::ct_mul_const(public_key,a,scalar);
            else if(op=="neg")result=pvac::ct_neg(public_key,a);
            else if(op=="add_const")result=pvac::ct_add_const(public_key,a,value,math);
            else if(op=="sub_const")result=pvac::ct_add_const(public_key,a,pvac::fp_neg(value),math);
            else if(op=="div_const")result=pvac::ct_div_const(public_key,a,value);
            else {
                result=a;
                if(op=="compact_edges")pvac::compact_edges(public_key,result);
                else if(op=="compact_layers")pvac::compact_layers(result);
                else if(op=="guard")pvac::guard_budget(public_key,result,"oracle");
                else if(op=="ubk")pvac::ubk_apply(public_key,result);
                else throw std::runtime_error("unknown oracle operation");
            }
            auto commitment=pvac::commit_ct(public_key,result);
            std::cout << "{\"bytes\":\"" << hex(pvac_ser::serialize_cipher(result)) << "\",\"commitment\":\""
                << hex(std::vector<uint8_t>(commitment.begin(),commitment.end())) << "\"}\n";
        } catch(const std::exception& error) { std::cout << "{\"error\":\"" << error.what() << "\"}\n"; }
    }
}
