#ifndef BLIND_SIG_LAZER_SHIM_H
#define BLIND_SIG_LAZER_SHIM_H

#include <stddef.h>
#include <stdint.h>

/* Reports: "LaZer Integration Feasibility" and "The Final-Signature Proof". */

#ifdef __cplusplus
extern "C" {
#endif

#define BS_LAZER_D64_DEGREE 64u
#define BS_LAZER_D64_COMMITMENT_COLUMNS 4u
#define BS_LAZER_D64_PADDED_COLUMNS 10u
#define BS_LAZER_D64_MATRIX_COEFFS                                           \
  (BS_LAZER_D64_COMMITMENT_COLUMNS * BS_LAZER_D64_DEGREE)
#define BS_LAZER_D64_STATEMENT_COEFFS BS_LAZER_D64_DEGREE
#define BS_LAZER_D64_WITNESS_COEFFS                                          \
  (BS_LAZER_D64_COMMITMENT_COLUMNS * BS_LAZER_D64_DEGREE)

#define BS_LAZER_SIG_D64_DEGREE 64u
#define BS_LAZER_SIG_D64_PREIMAGE_COLUMNS 51u
#define BS_LAZER_SIG_D64_RANDOMNESS_COLUMNS 2u
#define BS_LAZER_SIG_D64_BOUNDED_COLUMNS                                    \
  (BS_LAZER_SIG_D64_PREIMAGE_COLUMNS                                        \
   + BS_LAZER_SIG_D64_RANDOMNESS_COLUMNS)
#define BS_LAZER_SIG_D64_TAG_BITS 64u
#define BS_LAZER_SIG_D64_LINEAR_COEFFS                                      \
  (BS_LAZER_SIG_D64_BOUNDED_COLUMNS * BS_LAZER_SIG_D64_DEGREE)
#define BS_LAZER_SIG_D64_TAG_MATRIX_COEFFS                                  \
  (BS_LAZER_SIG_D64_DEGREE * BS_LAZER_SIG_D64_TAG_BITS)
#define BS_LAZER_SIG_D64_OFFSET_COEFFS BS_LAZER_SIG_D64_DEGREE
#define BS_LAZER_SIG_D64_WITNESS_COEFFS BS_LAZER_SIG_D64_LINEAR_COEFFS
#define BS_LAZER_SIG_D64_TAG_COEFFS BS_LAZER_SIG_D64_TAG_BITS

enum bs_lazer_status
{
  BS_LAZER_OK = 0,
  BS_LAZER_INVALID_ARGUMENT = -1,
  BS_LAZER_BUFFER_TOO_SMALL = -2,
  BS_LAZER_INTERNAL_ERROR = -3
};

/* Initialises the pinned LaZer library once per process. */
int bs_lazer_init (void);

/* Fixed transport length (LaZer's maximum encoded length) for this profile. */
size_t bs_lazer_d64_proof_len (void);

/* Expected encoded length for the advanced final-signature profile. */
size_t bs_lazer_sig_d64_proof_len (void);

/* Proves A * w - c = 0; coins may be NULL for system randomness. */
int bs_lazer_d64_prove (const int64_t *a, size_t a_len, const int64_t *c,
                        size_t c_len, const int64_t *w, size_t w_len,
                        const uint8_t ppseed[32], const uint8_t coins[32],
                        uint8_t *proof, size_t proof_capacity,
                        size_t *proof_len);

/* Returns 1 for an accepted proof, 0 for a rejected proof, or a negative
 * bs_lazer_status value for an invalid call or internal failure. */
int bs_lazer_d64_verify (const int64_t *a, size_t a_len, const int64_t *c,
                         size_t c_len, const uint8_t ppseed[32],
                         const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif
