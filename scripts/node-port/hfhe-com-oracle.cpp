#include "pvac/ops/recrypt_com.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace pvac;
static std::string hex(const std::array<uint8_t,32>& a){std::ostringstream s;s<<std::hex<<std::setfill('0');for(auto x:a)s<<std::setw(2)<<unsigned(x);return s.str();}
static void decision(const ComDecision& d){std::cout<<'['<<d.admitted<<','<<d.digest<<','<<d.bound<<','<<d.hiding<<','<<d.native<<','<<d.basis_closed<<','<<d.prebound<<','<<d.composable<<','<<d.rejects_unbound<<','<<d.rejects_basis_open<<','<<d.rejects_posthoc<<','<<d.rejects_nonclosed<<']';}
int main(){unsigned operation,mutation;uint64_t lo,hi,rlo,rhi,slo,shi;
 while(std::cin>>operation>>mutation>>lo>>hi>>rlo>>rhi>>slo>>shi){
 auto op=static_cast<ComOp>(operation);std::array<uint8_t,32> a{},b{},tag{};for(size_t i=0;i<32;++i){a[i]=i*7+1;b[i]=i*3+9;tag[i]=i*5+17;}
 auto left_open=make_com_open(Fp{lo,hi},a),right_open=make_com_open(Fp{rlo,rhi},b);auto left=make_com_cell(tag,left_open,true),right=make_com_cell(b,right_open,true);Fp scalar{slo,shi};
 auto out_open=make_com_open(fp_from_u64(0),std::array<uint8_t,32>{});
 switch(op){case ComOp::ADD:out_open=com_open_add(left_open,right_open);break;case ComOp::SUB:out_open=com_open_sub(left_open,right_open);break;case ComOp::SCALE:out_open=com_open_scale(left_open,scalar);break;case ComOp::ADD_CONST:out_open=com_open_add_const(left_open,scalar);break;case ComOp::PRODUCT:out_open=com_open_product(left_open,right_open);break;default:break;}
 auto out=make_com_expr(op,left,right,scalar,out_open);auto bare=make_com_expr(op,left,right,scalar);
 switch(mutation){case 1:left.prebound=false;break;case 2:right.prebound=false;break;case 3:left.kind=ComKind::EXPR;break;case 4:right.kind=ComKind::EXPR;break;case 5:out.kind=ComKind::NONE;break;case 6:out.bound=false;break;case 7:out.hiding=false;break;case 8:out.native=false;break;case 9:out.basis_closed=false;break;case 10:out.prebound=false;break;case 11:out.composable=false;break;case 12:out.tag[0]^=1;break;case 13:out.digest[0]^=1;break;case 14:left_open.blind[0]^=1;break;case 15:right_open.blind[0]^=1;break;case 16:out_open.blind[0]^=1;break;case 17:left_open.value=fp_add(left_open.value,fp_from_u64(1));break;case 18:right_open.value=fp_add(right_open.value,fp_from_u64(1));break;case 19:out_open.value=fp_add(out_open.value,fp_from_u64(1));break;case 20:scalar=fp_add(scalar,fp_from_u64(1));break;}
 std::cout<<"{\"value\":[\""<<out_open.value.lo<<"\",\""<<out_open.value.hi<<"\"],\"digests\":[\""<<hex(out_open.blind)<<"\",\""<<hex(out.tag)<<"\",\""<<hex(out.digest)<<"\",\""<<hex(bare.digest)<<"\"],\"opening\":";decision(decide_com_open(left,left_open));std::cout<<",\"claim\":";decision(decide_com_claim(out));std::cout<<",\"expression\":";decision(decide_com_expr_open(op,left,left_open,right,right_open,scalar,out,out_open));std::cout<<"}\n";
 }
}
