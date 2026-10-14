#include "pvac_serialize.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
static std::string hex(const std::vector<uint8_t>& bytes){std::ostringstream out;out<<std::hex<<std::setfill('0');for(auto b:bytes)out<<std::setw(2)<<unsigned(b);return out.str();}
int main(){std::string line;while(std::getline(std::cin,line)){
 std::vector<uint8_t>bytes;for(size_t i=0;i+1<line.size();i+=2)bytes.push_back(std::stoul(line.substr(i,2),nullptr,16));
 try{pvac_ser::Reader reader(bytes.data(),bytes.size());auto proof=pvac_ser::read_zero_proof_raw(reader);if(reader.failed)throw std::runtime_error(reader.error);pvac_ser::Writer writer;pvac_ser::write_zero_proof_raw(writer,proof);std::cout<<"{\"bytes\":\""<<hex(writer.buf)<<"\",\"bound\":"<<(proof.is_bound?"true":"false")<<"}\n";}
 catch(const std::exception& error){std::cout<<"{\"error\":\""<<error.what()<<"\"}\n";}
}}
