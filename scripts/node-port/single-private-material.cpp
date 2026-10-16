// Test-only deterministic keys and proofs from the unmodified adopted headers.
// Reuse the entropy adapter; no production entropy source is changed.
#define main zero_fixture_main
#include "hfhe-zero-oracle.cpp"
#undef main
static std::string bytes(const std::vector<uint8_t>& value) {
    return hex(value.data(), value.size());
}
int main() {
    Params p;p.B=126;p.m_bits=65;p.n_bits=17;p.h_col_wt=13;p.x_col_wt=7;
    p.err_wt=2;p.lpn_n=65;p.lpn_t=127;p.noise_entropy_bits=0;
    uint8_t seed[32];for(int i=0;i<32;i++)seed[i]=i;
    PubKey pk;SecKey sk;keygen_from_seed(p,pk,sk,seed);
    set_circuit_prf_profile(pk,sk,CircuitPrfProfile::MIMC_X5_V7);
    auto current=enc_value_seeded(pk,sk,20,seed);seed[0]=91;
    auto delta=enc_value_seeded(pk,sk,7,seed);
    auto remaining=ct_sub(pk,current,delta);
    auto blind=integer(19);auto commitment=pedersen_commit(integer(7),blind);
    reset_entropy(17401);
    auto proof=make_zero_proof_bound(pk,sk,delta,7,blind,ScalarRule::Wide);
    auto range=make_zero_proof_bound_range(pk,sk,remaining,13,blind,ScalarRule::Wide);
    reset_entropy(17402);auto delta_range=make_zero_proof_bound_range(pk,sk,delta,7,blind,ScalarRule::Wide);
    auto cipher_commitment=commit_ct(pk,delta);
    pvac_ser::Writer raw;pvac_ser::write_zero_proof_raw(raw,proof);
    auto legacy=pk;set_circuit_prf_profile(legacy,sk,CircuitPrfProfile::MIMC_X3_V6);
    std::cout<<"{\"public\":\""<<bytes(pvac_ser::serialize_pubkey(pk))
      <<"\",\"historical\":\""<<bytes(pvac_ser::serialize_pubkey(legacy))
      <<"\",\"current\":\""<<bytes(pvac_ser::serialize_cipher(current))
      <<"\",\"delta\":\""<<bytes(pvac_ser::serialize_cipher(delta))
      <<"\",\"proof\":\""<<bytes(raw.buf)
      <<"\",\"range\":\""<<bytes(pvac_ser::serialize_bound_range_proof(range))
      <<"\",\"delta_range\":\""<<bytes(pvac_ser::serialize_bound_range_proof(delta_range))
      <<"\",\"cipher_commitment\":\""<<hex(cipher_commitment.data(),32)
      <<"\",\"commitment\":\""<<hex(commitment.data(),32)
      <<"\",\"blinding\":\""<<hex(blind)<<"\"}\n";
}
