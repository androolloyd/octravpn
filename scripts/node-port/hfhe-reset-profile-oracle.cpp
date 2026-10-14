#include "pvac/ops/recrypt_proof_profile.hpp"
#include <iostream>
using namespace pvac;
int main(){unsigned int kind;size_t target,rounds,branches,opened,units;
 while(std::cin>>kind>>target>>rounds>>branches>>opened>>units){
  auto profile=plan_native_reset_proof_profile(static_cast<NativeResetProofProfileKind>(kind),target);
  NativeResetProofParams params{rounds,branches,opened,target};
  std::cout<<"["<<profile.params.rounds<<','<<profile.params.branches<<','<<profile.params.opened_branches<<','<<profile.params.target_bits<<','<<profile.soundness_bits<<','<<profile.branch_commits<<','<<profile.branch_openings<<','<<profile.trace_units<<','<<profile.commit_bytes<<','<<profile.opening_bytes<<','<<profile.transcript_bytes<<','<<profile.total_bytes<<','<<profile.baseline_bytes<<','<<profile.ratio_milli<<','<<profile.compact<<','<<profile.admitted<<','<<native_reset_rounds_for_target(target,branches,opened)<<','<<native_reset_proof_soundness_bits(params)<<','<<native_reset_proof_branch_commits(params)<<','<<native_reset_proof_branch_openings(params)<<','<<native_reset_proof_params_ok(params)<<','<<native_reset_profile_bytes(units)<<"]\n";
 }
}
