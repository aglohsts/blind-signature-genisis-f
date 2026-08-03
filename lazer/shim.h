#ifndef BLIND_SIG_LAZER_SHIM_H
#define BLIND_SIG_LAZER_SHIM_H

#include <stddef.h>
#include <stdint.h>

// report: "LaZer Integration" and "The Final-Signature Proof"

#ifdef __cplusplus
extern "C" {
#endif

#define BS_LAZER_D64_DEGREE 64u
#define BS_LAZER_D64_MODULUS 288230376151713349LL
#define BS_LAZER_D64_COMMITMENT_COLUMNS 4u
#define BS_LAZER_D64_PADDED_COLUMNS 10u
#define BS_LAZER_D64_MATRIX_COEFFS                                            \
    (BS_LAZER_D64_COMMITMENT_COLUMNS * BS_LAZER_D64_DEGREE)
#define BS_LAZER_D64_STATEMENT_COEFFS BS_LAZER_D64_DEGREE
#define BS_LAZER_D64_WITNESS_COEFFS                                           \
    (BS_LAZER_D64_COMMITMENT_COLUMNS * BS_LAZER_D64_DEGREE)

// the bounded witness is the concatenation (s, xi, r)
// its three blocks match the three exact l2 proofs of the generated profile
#define BS_LAZER_SIG_D64_DEGREE 64u
#define BS_LAZER_SIG_D64_PREIMAGE_COLUMNS 10u
#define BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_COLUMNS 2u
#define BS_LAZER_SIG_D64_RANDOMNESS_COLUMNS 2u
#define BS_LAZER_SIG_D64_BOUNDED_COLUMNS                                      \
    (BS_LAZER_SIG_D64_PREIMAGE_COLUMNS                                        \
     + BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_COLUMNS                           \
     + BS_LAZER_SIG_D64_RANDOMNESS_COLUMNS)
#define BS_LAZER_SIG_D64_TAG_BITS 64u
#define BS_LAZER_SIG_D64_LINEAR_COEFFS                                        \
    (BS_LAZER_SIG_D64_BOUNDED_COLUMNS * BS_LAZER_SIG_D64_DEGREE)
#define BS_LAZER_SIG_D64_TAG_MATRIX_COEFFS                                    \
    (BS_LAZER_SIG_D64_DEGREE * BS_LAZER_SIG_D64_TAG_BITS)
#define BS_LAZER_SIG_D64_OFFSET_COEFFS BS_LAZER_SIG_D64_DEGREE
#define BS_LAZER_SIG_D64_WITNESS_COEFFS BS_LAZER_SIG_D64_LINEAR_COEFFS
#define BS_LAZER_SIG_D64_TAG_COEFFS BS_LAZER_SIG_D64_TAG_BITS
#define BS_LAZER_SIG_D64_PREIMAGE_BOUND_SQ 6553600000u
#define BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_BOUND_SQ 2000u
#define BS_LAZER_SIG_D64_RANDOMNESS_BOUND_SQ 2000u
#define BS_LAZER_SIG_D64_PREIMAGE_BOUND_INF 80954
#define BS_LAZER_SIG_D64_SHORT_BOUND_INF 44

enum bs_lazer_status {
    BS_LAZER_OK = 0,
    BS_LAZER_INVALID_ARGUMENT = -1,
    BS_LAZER_BUFFER_TOO_SMALL = -2,
    BS_LAZER_INTERNAL_ERROR = -3
};

// initialise the pinned LaZer library once per process
int bs_lazer_init (void);

// the modulus each generated profile actually uses
// the advanced generator is given a bit length and picks its own prime, so these are read back rather than assumed
// a mismatch with the constant the shims reduce by would make the prover and the verifier disagree
uint64_t bs_lazer_d64_modulus (void);
uint64_t bs_lazer_sig_d64_modulus (void);

// fixed transport length (LaZer's maximum encoded length) for this profile
size_t bs_lazer_d64_proof_len (void);

// expected encoded length for the advanced final-signature profile
size_t bs_lazer_sig_d64_proof_len (void);

// guarded output capacity used by the advanced encoder
size_t bs_lazer_sig_d64_proof_capacity (void);

// return 1 exactly when the hidden values satisfy the fixed profile
int bs_lazer_sig_d64_witness_is_valid (const int64_t *witness,
                                       size_t witness_len, const int64_t *tag,
                                       size_t tag_len);

// prove linear * witness + tag_matrix * tag + offset = 0 coefficient-wise
int bs_lazer_sig_d64_prove (const int64_t *linear, size_t linear_len,
                            const int64_t *tag_matrix, size_t tag_matrix_len,
                            const int64_t *offset, size_t offset_len,
                            const int64_t *witness, size_t witness_len,
                            const int64_t *tag, size_t tag_len,
                            const uint8_t ppseed[32], const uint8_t coins[32],
                            uint8_t *proof, size_t proof_capacity,
                            size_t *proof_len);

// verify the same coefficient statement against an encoded proof
int bs_lazer_sig_d64_verify (const int64_t *linear, size_t linear_len,
                             const int64_t *tag_matrix, size_t tag_matrix_len,
                             const int64_t *offset, size_t offset_len,
                             const uint8_t ppseed[32], const uint8_t *proof,
                             size_t proof_len);

// prove A * w - c = 0; coins may be NULL for system randomness
int bs_lazer_d64_prove (const int64_t *a, size_t a_len, const int64_t *c,
                        size_t c_len, const int64_t *w, size_t w_len,
                        const uint8_t ppseed[32], const uint8_t coins[32],
                        uint8_t *proof, size_t proof_capacity,
                        size_t *proof_len);

// return 1 for an accepted proof, 0 for a rejected proof, or a negative bs_lazer_status value for an invalid call or internal failure
int bs_lazer_d64_verify (const int64_t *a, size_t a_len, const int64_t *c,
                         size_t c_len, const uint8_t ppseed[32],
                         const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif
