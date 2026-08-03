#ifndef BLIND_SIG_LAZER_SHIM_SIG_STATEMENT_H
#define BLIND_SIG_LAZER_SHIM_SIG_STATEMENT_H

#include "lazer.h"
#include "shim.h"

// one exact l2 proof per bounded block: the preimage s, the function randomness xi, and the commitment randomness r
// this count is the parameter Z of the generated profile, so it also moves the offset at which LaZer stores the caller-supplied evaluation equations
#define BS_SIG_D64_L2_PROOFS 3u
#define BS_SIG_D64_EVAL_OFFSET                                                \
    (2u * (BS_LAZER_SIG_D64_DEGREE - 1u) + 512u + 2u * BS_SIG_D64_L2_PROOFS   \
     + 1u)
#define BS_SIG_D64_EQUATIONS (2u * BS_LAZER_SIG_D64_DEGREE + 1u)
#define BS_SIG_D64_EVAL_SLOTS (BS_SIG_D64_EVAL_OFFSET + BS_SIG_D64_EQUATIONS)
#define BS_SIG_D64_VARIABLES (2u * (BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 3u))
#define BS_SIG_D64_NORM_EQUATION (BS_SIG_D64_EQUATIONS - 2u)
#define BS_SIG_D64_INVERSE_EQUATION (BS_SIG_D64_EQUATIONS - 1u)

typedef struct {
    spolymat_t quadratic[2];
    spolyvec_t linear[BS_SIG_D64_EQUATIONS];
    poly_t constant[BS_SIG_D64_EQUATIONS];
    spolymat_ptr quadratic_ptrs[BS_SIG_D64_EVAL_SLOTS];
    spolyvec_ptr linear_ptrs[BS_SIG_D64_EVAL_SLOTS];
    poly_ptr constant_ptrs[BS_SIG_D64_EVAL_SLOTS];
    polymat_t l2[BS_SIG_D64_L2_PROOFS];
    polymat_ptr l2_ptrs[BS_SIG_D64_L2_PROOFS];
    polymat_t binary_m;
    polymat_t arp_s;
} bs_sig_d64_statement;

void bs_sig_d64_statement_init (bs_sig_d64_statement *statement,
                                const int64_t *linear,
                                const int64_t *tag_matrix,
                                const int64_t *offset);

void bs_sig_d64_statement_clear (bs_sig_d64_statement *statement);

#endif
