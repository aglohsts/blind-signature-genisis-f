#include "shim.h"

#include <pthread.h>
#include <string.h>

#include "lazer.h"
#include "params_d64.h"
#include "params_sig_d64.h"

/* Reports: "LaZer Integration Feasibility" and "The Final-Signature Proof". */

#define BS_LAZER_D64_PADDED_COEFFS                                           \
  (BS_LAZER_D64_PADDED_COLUMNS * BS_LAZER_D64_DEGREE)

static pthread_once_t bs_lazer_once = PTHREAD_ONCE_INIT;

static void
bs_lazer_init_once (void)
{
  lazer_init ();
}

int
bs_lazer_init (void)
{
  return pthread_once (&bs_lazer_once, bs_lazer_init_once) == 0
             ? BS_LAZER_OK
             : BS_LAZER_INTERNAL_ERROR;
}

size_t
bs_lazer_d64_proof_len (void)
{
  return (size_t)lin_params_get_prooflen (blind_sig_com_d64);
}

size_t
bs_lazer_sig_d64_proof_len (void)
{
  return (size_t)blind_sig_sig_d64->prooflen;
}

static int64_t
center_mod_257 (int64_t value)
{
  int64_t reduced = value % 257;
  if (reduced < 0)
    reduced += 257;
  if (reduced > 128)
    reduced -= 257;
  return reduced;
}

static int
witness_is_in_profile (const int64_t *w)
{
  unsigned int i;
  __int128 message_sq = 0;
  __int128 randomness_sq = 0;

  for (i = 0; i < 2 * BS_LAZER_D64_DEGREE; i++)
    {
      if (w[i] < -20 || w[i] > 20)
        return 0;
      message_sq += (__int128)w[i] * w[i];
    }
  for (; i < BS_LAZER_D64_WITNESS_COEFFS; i++)
    {
      if (w[i] < -20 || w[i] > 20)
        return 0;
      randomness_sq += (__int128)w[i] * w[i];
    }

  return message_sq <= 16 && randomness_sq <= 2000;
}

static void
load_statement (polymat_t A, polyvec_t t, const int64_t *a,
                const int64_t *c)
{
  int64_t padded_a[BS_LAZER_D64_PADDED_COEFFS] = { 0 };
  int64_t normalized_c[BS_LAZER_D64_STATEMENT_COEFFS];
  size_t i;

  for (i = 0; i < BS_LAZER_D64_MATRIX_COEFFS; i++)
    padded_a[i] = center_mod_257 (a[i]);
  for (i = 0; i < BS_LAZER_D64_STATEMENT_COEFFS; i++)
    normalized_c[i] = center_mod_257 (c[i]);

  polymat_set_i64 (A, padded_a);
  polyvec_set_coeffvec_i64 (t, normalized_c);
  polyvec_neg_self (t);
}

int
bs_lazer_d64_prove (const int64_t *a, size_t a_len, const int64_t *c,
                    size_t c_len, const int64_t *w, size_t w_len,
                    const uint8_t ppseed[32], const uint8_t coins[32],
                    uint8_t *proof, size_t proof_capacity, size_t *proof_len)
{
  const size_t expected = bs_lazer_d64_proof_len ();
  int64_t padded_w[BS_LAZER_D64_PADDED_COEFFS] = { 0 };
  size_t actual = 0;
  size_t i;
  int status;
  INT_T (q, 1);
  POLYRING_T (ring, q, BS_LAZER_D64_DEGREE);
  polymat_t A;
  polyvec_t witness;
  polyvec_t t;
  lin_prover_state_t prover;

  if (proof_len == NULL)
    return BS_LAZER_INVALID_ARGUMENT;
  *proof_len = expected;
  if (a == NULL || c == NULL || w == NULL || ppseed == NULL
      || a_len != BS_LAZER_D64_MATRIX_COEFFS
      || c_len != BS_LAZER_D64_STATEMENT_COEFFS
      || w_len != BS_LAZER_D64_WITNESS_COEFFS || !witness_is_in_profile (w))
    return BS_LAZER_INVALID_ARGUMENT;
  if (proof_capacity < expected)
    return BS_LAZER_BUFFER_TOO_SMALL;
  if (proof == NULL)
    return BS_LAZER_INVALID_ARGUMENT;
  status = bs_lazer_init ();
  if (status != BS_LAZER_OK)
    return status;

  int_set_i64 (q, 257);
  polymat_alloc (A, ring, 1, BS_LAZER_D64_PADDED_COLUMNS);
  polyvec_alloc (witness, ring, BS_LAZER_D64_PADDED_COLUMNS);
  polyvec_alloc (t, ring, 1);

  load_statement (A, t, a, c);
  for (i = 0; i < BS_LAZER_D64_WITNESS_COEFFS; i++)
    padded_w[i] = w[i];
  polyvec_set_coeffvec_i64 (witness, padded_w);

  lin_prover_init (prover, ppseed, blind_sig_com_d64);
  lin_prover_set_statement (prover, A, t);
  lin_prover_set_witness (prover, witness);
  memset (proof, 0, expected);
  lin_prover_prove (prover, proof, &actual, coins);
  lin_prover_clear (prover);

  polymat_free (A);
  polyvec_free (witness);
  polyvec_free (t);

  *proof_len = expected;
  return actual > 0 && actual <= expected ? BS_LAZER_OK
                                          : BS_LAZER_INTERNAL_ERROR;
}

int
bs_lazer_d64_verify (const int64_t *a, size_t a_len, const int64_t *c,
                     size_t c_len, const uint8_t ppseed[32],
                     const uint8_t *proof, size_t proof_len)
{
  const size_t expected = bs_lazer_d64_proof_len ();
  size_t consumed = 0;
  int accept;
  int status;
  INT_T (q, 1);
  POLYRING_T (ring, q, BS_LAZER_D64_DEGREE);
  polymat_t A;
  polyvec_t t;
  lin_verifier_state_t verifier;

  if (a == NULL || c == NULL || ppseed == NULL || proof == NULL
      || a_len != BS_LAZER_D64_MATRIX_COEFFS
      || c_len != BS_LAZER_D64_STATEMENT_COEFFS)
    return BS_LAZER_INVALID_ARGUMENT;
  if (proof_len != expected)
    return 0;
  status = bs_lazer_init ();
  if (status != BS_LAZER_OK)
    return status;

  int_set_i64 (q, 257);
  polymat_alloc (A, ring, 1, BS_LAZER_D64_PADDED_COLUMNS);
  polyvec_alloc (t, ring, 1);
  load_statement (A, t, a, c);

  lin_verifier_init (verifier, ppseed, blind_sig_com_d64);
  lin_verifier_set_statement (verifier, A, t);
  accept = lin_verifier_verify (verifier, proof, &consumed);
  lin_verifier_clear (verifier);

  polymat_free (A);
  polyvec_free (t);

  if (accept != 1 || consumed == 0 || consumed > expected)
    return 0;
  for (; consumed < expected; consumed++)
    if (proof[consumed] != 0)
      return 0;
  return 1;
}
