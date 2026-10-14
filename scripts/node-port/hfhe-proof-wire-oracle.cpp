#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
static std::string hex(const std::vector<uint8_t>& bytes){std::ostringstream out;out<<std::hex<<std::setfill('0');for(auto b:bytes)out<<std::setw(2)<<unsigned(b);return out.str();}
int main(){std::string line;while(std::getline(std::cin,line)){
 std::vector<uint8_t>bytes;for(size_t i=0;i+1<line.size();i+=2)bytes.push_back(std::stoul(line.substr(i,2),nullptr,16));
 try{auto proof=pvac_ser::deserialize_zero_proof(bytes.data(),bytes.size());std::cout<<"{\"bytes\":\""<<hex(pvac_ser::serialize_zero_proof(proof))<<"\",\"bound\":"<<(proof.is_bound?"true":"false")<<"}\n";}
 catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
}}
