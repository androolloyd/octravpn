#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
static std::string hex(const std::vector<uint8_t>& bytes){std::ostringstream out;out<<std::hex<<std::setfill('0');for(auto b:bytes)out<<std::setw(2)<<unsigned(b);return out.str();}
int main(){std::string line;while(std::getline(std::cin,line)){
 std::vector<uint8_t>bytes;for(size_t i=0;i+1<line.size();i+=2)bytes.push_back(std::stoul(line.substr(i,2),nullptr,16));
 try{auto proof=pvac_ser::deserialize_range_proof_any(bytes.data(),bytes.size());auto encoded=proof.format==pvac_ser::RP_OLD?pvac_ser::serialize_range_proof(proof.old_proof):proof.format==pvac_ser::RP_AGGREGATED?pvac_ser::serialize_agg_range_proof(proof.agg_proof):pvac_ser::serialize_bound_range_proof(proof.bound_proof);std::cout<<"{\"bytes\":\""<<hex(encoded)<<"\",\"format\":"<<int(proof.format)<<"}\n";}
 catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
}}
