#include "shim.h"

#include <stdlib.h>
#include <string.h>

#include "lazer.h"
#include "params_sig_d64.h"
#include "shim_sig_statement.h"

/* Report: "The Final-Signature Proof". */

#define BS_SIG_D64_Q 288230376151713349ULL

#define BS_SIG_D64_PREIMAGE_COEFFS                                          \
  ((size_t)BS_LAZER_SIG_D64_PREIMAGE_COLUMNS * BS_LAZER_SIG_D64_DEGREE)
#define BS_SIG_D64_FUNCTION_RANDOMNESS_COEFFS                               \
  ((size_t)BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_COLUMNS                     \
   * BS_LAZER_SIG_D64_DEGREE)

static uint64_t
preimage_norm_sq (const int64_t *witness)
{
  uint64_t norm = 0;
  size_t i;

  for (i = 0; i < BS_SIG_D64_PREIMAGE_COEFFS; i++)
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

/* Accumulates one bounded block and checks its infinity bound. */
static int
block_norm_sq (const int64_t *witness, size_t first, size_t count,
               int64_t bound_inf, uint64_t *norm_sq)
{
  size_t i;

  *norm_sq = 0;
  for (i = first; i < first + count; i++)
    {
      if (witness[i] < -bound_inf || witness[i] > bound_inf)
        return 0;
      *norm_sq += (uint64_t)(witness[i] * witness[i]);
    }
  return 1;
}

int
bs_lazer_sig_d64_witness_is_valid (const int64_t *witness,
                                   size_t witness_len, const int64_t *tag,
                                   size_t tag_len)
{
  uint64_t preimage_sq;
  uint64_t function_randomness_sq;
  uint64_t randomness_sq;
  size_t i;

  if (witness == NULL || tag == NULL
      || witness_len != BS_LAZER_SIG_D64_WITNESS_COEFFS
      || tag_len != BS_LAZER_SIG_D64_TAG_COEFFS)
    return 0;

  if (!block_norm_sq (witness, 0, BS_SIG_D64_PREIMAGE_COEFFS,
                      BS_LAZER_SIG_D64_PREIMAGE_BOUND_INF, &preimage_sq))
    return 0;
  if (!block_norm_sq (witness, BS_SIG_D64_PREIMAGE_COEFFS,
                      BS_SIG_D64_FUNCTION_RANDOMNESS_COEFFS,
                      BS_LAZER_SIG_D64_SHORT_BOUND_INF,
                      &function_randomness_sq))
    return 0;
  if (!block_norm_sq (witness,
                      BS_SIG_D64_PREIMAGE_COEFFS
                          + BS_SIG_D64_FUNCTION_RANDOMNESS_COEFFS,
                      witness_len - BS_SIG_D64_PREIMAGE_COEFFS
                          - BS_SIG_D64_FUNCTION_RANDOMNESS_COEFFS,
                      BS_LAZER_SIG_D64_SHORT_BOUND_INF, &randomness_sq))
    return 0;

  for (i = 0; i < tag_len; i++)
    if (tag[i] != 0 && tag[i] != 1)
      return 0;

  return preimage_sq > 0
         && preimage_sq <= BS_LAZER_SIG_D64_PREIMAGE_BOUND_SQ
         && function_randomness_sq
                <= BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_BOUND_SQ
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

int
bs_lazer_sig_d64_verify (
    const int64_t *linear, size_t linear_len, const int64_t *tag_matrix,
    size_t tag_matrix_len, const int64_t *offset, size_t offset_len,
    const uint8_t ppseed[32], const uint8_t *proof, size_t proof_len)
{
  const size_t guard_capacity = bs_lazer_sig_d64_proof_capacity ();
  uint8_t *guarded_proof;
  size_t consumed = 0;
  int accept;
  int status;
  bs_sig_d64_statement statement;
  lnp_verifier_state_t verifier;

  if (linear == NULL || tag_matrix == NULL || offset == NULL
      || ppseed == NULL || proof == NULL
      || linear_len != BS_LAZER_SIG_D64_LINEAR_COEFFS
      || tag_matrix_len != BS_LAZER_SIG_D64_TAG_MATRIX_COEFFS
      || offset_len != BS_LAZER_SIG_D64_OFFSET_COEFFS || proof_len == 0
      || proof_len > guard_capacity)
    return BS_LAZER_INVALID_ARGUMENT;
  status = bs_lazer_init ();
  if (status != BS_LAZER_OK)
    return status;

  guarded_proof = calloc (guard_capacity, 1);
  if (guarded_proof == NULL)
    return BS_LAZER_INTERNAL_ERROR;
  memcpy (guarded_proof, proof, proof_len);

  bs_sig_d64_statement_init (&statement, linear, tag_matrix, offset);
  lnp_verifier_init (verifier, ppseed, blind_sig_sig_d64);
  lnp_verifier_set_statement_evaleqs (
      verifier, statement.quadratic_ptrs, statement.linear_ptrs,
      statement.constant_ptrs, BS_SIG_D64_EQUATIONS);
  lnp_verifier_set_statement_l2 (verifier, statement.l2_ptrs, NULL, NULL);
  lnp_verifier_set_statement_bin (verifier, NULL, statement.binary_m, NULL);
  lnp_verifier_set_statement_arp (verifier, statement.arp_s, NULL, NULL);
  accept = lnp_verifier_verify (verifier, guarded_proof, &consumed);

  lnp_verifier_clear (verifier);
  bs_sig_d64_statement_clear (&statement);
  free (guarded_proof);

  return accept == 1 && consumed == proof_len ? 1 : 0;
}
