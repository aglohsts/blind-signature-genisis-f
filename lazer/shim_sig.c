#include "shim.h"

#include <string.h>

#include "lazer.h"
#include "params_sig_d64.h"
#include "shim_sig_statement.h"

/* Report: "The Final-Signature Proof". */

#define BS_SIG_D64_Q 281474976711349ULL

static uint64_t
preimage_norm_sq (const int64_t *witness)
{
  const size_t count
      = BS_LAZER_SIG_D64_PREIMAGE_COLUMNS * BS_LAZER_SIG_D64_DEGREE;
  uint64_t norm = 0;
  size_t i;

  for (i = 0; i < count; i++)
    norm += (uint64_t)(witness[i] * witness[i]);
  return norm;
}

static uint64_t
mod_inverse (uint64_t value)
{
  uint64_t result = 1;
  uint64_t base = value;
  uint64_t exponent = BS_SIG_D64_Q - 2;

  while (exponent > 0)
    {
      if ((exponent & 1u) != 0)
        result = (uint64_t)((unsigned __int128)result * base % BS_SIG_D64_Q);
      base = (uint64_t)((unsigned __int128)base * base % BS_SIG_D64_Q);
      exponent >>= 1;
    }
  return result;
}

int
bs_lazer_sig_d64_witness_is_valid (const int64_t *witness,
                                   size_t witness_len, const int64_t *tag,
                                   size_t tag_len)
{
  const size_t preimage_coeffs
      = BS_LAZER_SIG_D64_PREIMAGE_COLUMNS * BS_LAZER_SIG_D64_DEGREE;
  uint64_t preimage_sq = 0;
  uint64_t randomness_sq = 0;
  size_t i;

  if (witness == NULL || tag == NULL
      || witness_len != BS_LAZER_SIG_D64_WITNESS_COEFFS
      || tag_len != BS_LAZER_SIG_D64_TAG_COEFFS)
    return 0;

  for (i = 0; i < preimage_coeffs; i++)
    {
      if (witness[i] < -5713 || witness[i] > 5713)
        return 0;
      preimage_sq += (uint64_t)(witness[i] * witness[i]);
    }
  for (; i < witness_len; i++)
    {
      if (witness[i] < -44 || witness[i] > 44)
        return 0;
      randomness_sq += (uint64_t)(witness[i] * witness[i]);
    }
  for (i = 0; i < tag_len; i++)
    if (tag[i] != 0 && tag[i] != 1)
      return 0;

  return preimage_sq > 0
         && preimage_sq <= BS_LAZER_SIG_D64_PREIMAGE_BOUND_SQ
         && randomness_sq <= BS_LAZER_SIG_D64_RANDOMNESS_BOUND_SQ;
}

int
bs_lazer_sig_d64_prove (
    const int64_t *linear, size_t linear_len, const int64_t *tag_matrix,
    size_t tag_matrix_len, const int64_t *offset, size_t offset_len,
    const int64_t *witness, size_t witness_len, const int64_t *tag,
    size_t tag_len, const uint8_t ppseed[32], const uint8_t coins[32],
    uint8_t *proof, size_t proof_capacity, size_t *proof_len)
{
  const size_t required_capacity = bs_lazer_sig_d64_proof_capacity ();
  int64_t unbounded_coeffs[3 * BS_LAZER_SIG_D64_DEGREE] = { 0 };
  uint8_t random_coins[32];
  const uint8_t *prover_coins = coins;
  uint64_t norm;
  size_t actual = 0;
  int status;
  bs_sig_d64_statement statement;
  polyvec_t bounded;
  polyvec_t unbounded;
  lnp_prover_state_t prover;

  if (proof_len == NULL)
    return BS_LAZER_INVALID_ARGUMENT;
  *proof_len = required_capacity;
  if (linear == NULL || tag_matrix == NULL || offset == NULL
      || witness == NULL || tag == NULL || ppseed == NULL || proof == NULL
      || linear_len != BS_LAZER_SIG_D64_LINEAR_COEFFS
      || tag_matrix_len != BS_LAZER_SIG_D64_TAG_MATRIX_COEFFS
      || offset_len != BS_LAZER_SIG_D64_OFFSET_COEFFS
      || !bs_lazer_sig_d64_witness_is_valid (witness, witness_len, tag,
                                             tag_len))
    return BS_LAZER_INVALID_ARGUMENT;
  if (proof_capacity < required_capacity)
    return BS_LAZER_BUFFER_TOO_SMALL;
  status = bs_lazer_init ();
  if (status != BS_LAZER_OK)
    return status;

  norm = preimage_norm_sq (witness);
  memcpy (unbounded_coeffs, tag,
          BS_LAZER_SIG_D64_TAG_COEFFS * sizeof (*tag));
  unbounded_coeffs[BS_LAZER_SIG_D64_DEGREE] = (int64_t)norm;
  unbounded_coeffs[2 * BS_LAZER_SIG_D64_DEGREE]
      = (int64_t)mod_inverse (norm);

  bs_sig_d64_statement_init (&statement, linear, tag_matrix, offset);
  polyvec_alloc (bounded, blind_sig_sig_d64_ring,
                 BS_LAZER_SIG_D64_BOUNDED_COLUMNS);
  polyvec_alloc (unbounded, blind_sig_sig_d64_ring, 3);
  polyvec_set_coeffvec_i64 (bounded, witness);
  polyvec_set_coeffvec_i64 (unbounded, unbounded_coeffs);

  lnp_prover_init (prover, ppseed, blind_sig_sig_d64);
  lnp_prover_set_statement_evaleqs (
      prover, statement.quadratic_ptrs, statement.linear_ptrs,
      statement.constant_ptrs, BS_SIG_D64_EQUATIONS);
  lnp_prover_set_statement_l2 (prover, statement.l2_ptrs, NULL, NULL);
  lnp_prover_set_statement_bin (prover, NULL, statement.binary_m, NULL);
  lnp_prover_set_statement_arp (prover, statement.arp_s, NULL, NULL);
  lnp_prover_set_witness (prover, bounded, unbounded);

  if (prover_coins == NULL)
    {
      bytes_urandom (random_coins, sizeof (random_coins));
      prover_coins = random_coins;
    }
  memset (proof, 0, required_capacity);
  lnp_prover_prove (prover, proof, &actual, prover_coins);

  lnp_prover_clear (prover);
  polyvec_free (bounded);
  polyvec_free (unbounded);
  bs_sig_d64_statement_clear (&statement);

  if (actual == 0 || actual > required_capacity)
    return BS_LAZER_INTERNAL_ERROR;
  *proof_len = actual;
  return BS_LAZER_OK;
}
