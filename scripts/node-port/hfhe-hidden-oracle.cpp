#include "pvac/ops/recrypt_chosen_privacy.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace pvac;
static std::string hex(const std::array<uint8_t,32>& a){std::ostringstream s;s<<std::hex<<std::setfill('0');for(auto x:a)s<<std::setw(2)<<unsigned(x);return s.str();}
int main(){size_t count,terms,alpha,row,target,slots,query,bits,flags,cert,mutation,budget;
 while(std::cin>>count>>terms>>alpha>>row>>target>>slots>>query>>bits>>flags>>cert>>mutation>>budget){
 HiddenCoeffBound bound{terms,alpha,row};HiddenCoeffMaterial hm;hm.bound=bound;HiddenCoeffStmt hs;hs.bound=bound;
 for(size_t i=0;i<count;++i){std::array<uint8_t,32> t{};for(size_t j=0;j<32;++j)t[j]=(i*31+j*7+11)&255;hm.row_tags.push_back(t);hs.alpha.push_back(fp_from_u64(i*19+3));}
 HiddenCoeffProfile hp;hp.reusable=flags&1;hp.visible_output=flags&2;hp.statement_bound=flags&4;hp.transcript_bound=flags&8;hp.cert=static_cast<HiddenCoeffCertKind>(cert);
 auto plan=plan_hidden_coeff(bound);auto hd=decide_hidden_coeff_profile(hp);auto ht=make_native_hidden_coeff_transcript(hm,hs);
 std::cout<<"{\"plan\":["<<plan.sum_bits<<','<<plan.needs_p_correction<<','<<plan.needs_wide_correction<<','<<plan.admitted<<"],\"profile\":["<<hd.admitted<<','<<hd.rejects_basis_oracle<<','<<hd.needs_native_certificate<<','<<accept_native_public_reset_profile(hp,plan)<<"],\"hidden\":[\""<<hex(hm.row_tags.empty()?hidden_coeff_material_digest(hm):hidden_coeff_material_digest(hm))<<"\",\""<<hex(hidden_coeff_stmt_digest(hs))<<"\",\""<<hex(ht.aggregate_tag)<<"\","<<verify_native_hidden_coeff_transcript(hm,hs,ht)<<"],";
 try{
 auto m=make_native_reset_chosen_material(hm,target,slots);NativeResetChosenStmt s;s.coeff=hs;s.target_terms=target;s.slots=slots;s.query=query;
 auto o=make_native_reset_hidden_output(m,s);auto t=make_native_reset_chosen_transcript(m,s,o);
 NativeResetChosenPolicy p;p.reusable=p.hidden_output=p.statement_bound=p.transcript_bound=p.material_bound=p.no_basis_oracle=p.native_backend=true;p.max_queries=64;p.cert=HiddenCoeffCertKind::PVAC_NATIVE;
 NativeResetReusableBudget b;b.target_bits=bits;
 switch(budget){case 1:b.proof=NativeResetProofProfileKind::SHA_COMPAT;break;case 2:b.max_trace_units=0;break;case 3:b.max_output_tags=0;break;case 4:b.max_proof_bytes=0;break;case 5:b.proof=NativeResetProofProfileKind::NONE;break;}
 switch(mutation){
 case 1:p.reusable=false;break;case 2:p.hidden_output=false;break;case 3:p.statement_bound=false;break;case 4:p.transcript_bound=false;break;case 5:p.material_bound=false;break;case 6:p.no_basis_oracle=false;break;case 7:p.native_backend=false;break;case 8:p.max_queries=0;break;case 9:p.cert=HiddenCoeffCertKind::NONE;break;
 case 10:m.kind=NativeResetChosenMaterialKind::RAW_ROWS;break;case 11:m.kind=NativeResetChosenMaterialKind::VISIBLE_COEFFS;break;case 12:m.reusable=false;break;case 13:m.has_raw_rows=true;break;case 14:m.visible_coeffs=true;break;case 15:m.hides_rows=false;break;case 16:m.no_basis_oracle=false;break;case 17:m.native_backend=false;break;case 18:m.coeff.bound.terms++;break;case 19:m.target_terms++;break;case 20:m.slots++;break;
 case 21:s.coeff.bound.alpha_bits++;break;case 22:s.coeff.bound.row_bits++;break;case 23:s.coeff.alpha.push_back(fp_from_u64(4));break;case 24:s.target_terms++;break;case 25:s.slots++;break;case 26:s.query=64;break;
 case 27:o.hidden_coeffs=false;break;case 28:o.visible_beta=true;break;case 29:o.material_digest[0]^=1;break;case 30:o.statement_digest[0]^=1;break;case 31:o.output_digest[0]^=1;break;case 32:o.coeff_tags.clear();break;case 33:o.coeff_tags[0][0]^=1;break;
 case 34:t.plan.sum_bits++;break;case 35:t.plan.needs_p_correction=!t.plan.needs_p_correction;break;case 36:t.plan.needs_wide_correction=!t.plan.needs_wide_correction;break;case 37:t.plan.admitted=!t.plan.admitted;break;case 38:t.material_digest[0]^=1;break;case 39:t.statement_digest[0]^=1;break;case 40:t.output_digest[0]^=1;break;case 41:t.transcript_digest[0]^=1;break;case 42:t.statement_bound=false;break;case 43:t.material_bound=false;break;case 44:t.hidden_output=false;break;case 45:t.no_basis_oracle=false;break;case 46:t.native_backend=false;break;
 }
 auto d=decide_native_reset_chosen_statement(p,m,s,o,t);auto r=decide_native_reset_reusable_statement(p,m,s,o,t,b);
 std::cout<<"\"chosen\":["<<d.admitted<<','<<d.policy<<','<<d.material<<','<<d.statement<<','<<d.output<<','<<d.transcript<<','<<d.privacy<<','<<d.rejects_raw<<','<<d.rejects_visible<<','<<d.rejects_unbound<<','<<d.rejects_basis_oracle<<','<<d.rejects_query_budget<<','<<d.rejects_wide<<"],\"reusable\":["<<r.admitted<<','<<r.privacy<<','<<r.proof<<','<<r.compact<<','<<r.output<<','<<r.budget<<','<<r.rejects_sha_compat<<','<<r.rejects_noncompact<<','<<r.rejects_underbudget<<','<<r.rejects_output_wide<<','<<r.rejects_proof_wide<<"],\"digests\":[\""<<hex(native_chosen_material_digest(m))<<"\",\""<<hex(native_chosen_stmt_digest(s))<<"\",\""<<hex(native_chosen_output_digest(o))<<"\",\""<<hex(native_chosen_transcript_digest(t))<<"\"]}\n";
 }catch(const std::exception& e){std::cout<<"\"error\":\""<<e.what()<<"\"}\n";}
 }
}
