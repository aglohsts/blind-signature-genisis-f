#include "shim_sig_statement.h"

#include <string.h>

#include "params_sig_d64.h"

/* Report: "The Final-Signature Proof".
 *
 * The statement is the coefficient-level form of
 *
 *     A s - kappa xi - B_2 r - G enc(mu) - B_1 m = 0,
 *
 * written as `linear * (s, xi, r) + tag_matrix * enc(mu) + offset = 0`.
 * One evaluation equation is emitted per coefficient of the ring
 * equation. Two further equations prove that the preimage is non-zero:
 * the first binds an unbounded variable h to the squared norm of s, and
 * the second forces h to have an inverse u.
 */

#define BS_SIG_D64_Q 288230376151713349LL

static int64_t
center_mod_sig_q (int64_t value)
{
  int64_t reduced = value % BS_SIG_D64_Q;
  if (reduced < 0)
    reduced += BS_SIG_D64_Q;
  if (reduced > BS_SIG_D64_Q / 2)
    reduced -= BS_SIG_D64_Q;
  return reduced;
}

static void
set_constant_coefficient (poly_ptr poly, int64_t value)
{
  poly_set_zero (poly);
  int_set_i64 (poly_get_coeff (poly, 0), center_mod_sig_q (value));
}

static void
set_coefficient_vector (poly_ptr poly, const int64_t *values)
{
  unsigned int i;

  poly_set_zero (poly);
  for (i = 0; i < BS_LAZER_SIG_D64_DEGREE; i++)
    int_set_i64 (poly_get_coeff (poly, i), center_mod_sig_q (values[i]));
}

static void
set_rotated_automorphism (poly_ptr poly, const int64_t *values,
                          unsigned int shift)
{
  unsigned int source;

  poly_set_zero (poly);
  for (source = 0; source < BS_LAZER_SIG_D64_DEGREE; source++)
    {
      unsigned int exponent = source == 0 ? 0 : BS_LAZER_SIG_D64_DEGREE - source;
      int64_t value = center_mod_sig_q (values[source]);

      if (source != 0)
        value = -value;
      exponent += shift;
      if (exponent >= BS_LAZER_SIG_D64_DEGREE)
        {
          exponent -= BS_LAZER_SIG_D64_DEGREE;
          value = -value;
        }
      int_set_i64 (poly_get_coeff (poly, exponent), value);
    }
}

static void
set_identity_entry (polymat_t matrix, unsigned int row, unsigned int column)
{
  poly_ptr entry = polymat_get_elem (matrix, row, column);
  int_set_i64 (poly_get_coeff (entry, 0), 1);
}

/* Selects `rows` consecutive bounded columns starting at `first`. */
static void
set_selector (polymat_t matrix, unsigned int rows, unsigned int first)
{
  unsigned int row;

  polymat_alloc (matrix, blind_sig_sig_d64_ring, rows,
                 BS_LAZER_SIG_D64_BOUNDED_COLUMNS);
  polymat_set_zero (matrix);
  for (row = 0; row < rows; row++)
    set_identity_entry (matrix, row, first + row);
}

void
bs_sig_d64_statement_init (bs_sig_d64_statement *statement,
                           const int64_t *linear,
                           const int64_t *tag_matrix,
                           const int64_t *offset)
{
  const unsigned int h_auto
      = 2u * (BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 1u) + 1u;
  const unsigned int h_plain
      = 2u * (BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 1u);
  const unsigned int u_auto
      = 2u * (BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 2u) + 1u;
  const unsigned int tag_auto
      = 2u * BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 1u;
  unsigned int equation;
  unsigned int row;
  unsigned int column;

  memset (statement, 0, sizeof (*statement));
  for (equation = 0; equation < BS_SIG_D64_EQUATIONS; equation++)
    {
      const unsigned int slot = BS_SIG_D64_EVAL_OFFSET + equation;
      spolyvec_alloc (statement->linear[equation], blind_sig_sig_d64_ring,
                      BS_SIG_D64_VARIABLES,
                      BS_LAZER_SIG_D64_BOUNDED_COLUMNS + 1u);
      poly_alloc (statement->constant[equation], blind_sig_sig_d64_ring);
      poly_set_zero (statement->constant[equation]);
      statement->linear_ptrs[slot] = statement->linear[equation];
      statement->constant_ptrs[slot] = statement->constant[equation];
    }

  for (row = 0; row < BS_LAZER_SIG_D64_DEGREE; row++)
    {
      spolyvec_ptr equation = statement->linear[row];
      poly_ptr entry;

      for (column = 0; column < BS_LAZER_SIG_D64_BOUNDED_COLUMNS; column++)
        {
          entry = spolyvec_insert_elem (equation, 2u * column + 1u);
          set_rotated_automorphism (
              entry, linear + column * BS_LAZER_SIG_D64_DEGREE, row);
        }
      entry = spolyvec_insert_elem (equation, tag_auto);
      set_coefficient_vector (
          entry, tag_matrix + row * BS_LAZER_SIG_D64_TAG_BITS);
      set_constant_coefficient (statement->constant[row], offset[row]);
      spolyvec_sort (statement->linear[row]);
    }

  for (row = 1; row < BS_LAZER_SIG_D64_DEGREE; row++)
    {
      const unsigned int index = BS_LAZER_SIG_D64_DEGREE + row - 1u;
      poly_ptr entry = spolyvec_insert_elem (statement->linear[index], h_auto);
      poly_set_zero (entry);
      int_set_i64 (poly_get_coeff (entry, row), 1);
      spolyvec_sort (statement->linear[index]);
    }

  spolymat_alloc (statement->quadratic[0], blind_sig_sig_d64_ring,
                  BS_SIG_D64_VARIABLES, BS_SIG_D64_VARIABLES,
                  BS_LAZER_SIG_D64_PREIMAGE_COLUMNS);
  for (column = 0; column < BS_LAZER_SIG_D64_PREIMAGE_COLUMNS; column++)
    set_constant_coefficient (
        spolymat_insert_elem (statement->quadratic[0], 2u * column,
                              2u * column + 1u),
        -1);
  statement->quadratic_ptrs[BS_SIG_D64_EVAL_OFFSET
                             + BS_SIG_D64_NORM_EQUATION]
      = statement->quadratic[0];
  set_constant_coefficient (
      spolyvec_insert_elem (statement->linear[BS_SIG_D64_NORM_EQUATION],
                            h_auto),
      1);
  spolyvec_sort (statement->linear[BS_SIG_D64_NORM_EQUATION]);
  spolymat_sort (statement->quadratic[0]);

  spolymat_alloc (statement->quadratic[1], blind_sig_sig_d64_ring,
                  BS_SIG_D64_VARIABLES, BS_SIG_D64_VARIABLES, 1);
  set_constant_coefficient (
      spolymat_insert_elem (statement->quadratic[1], h_plain, u_auto), 1);
  statement->quadratic_ptrs[BS_SIG_D64_EVAL_OFFSET
                             + BS_SIG_D64_INVERSE_EQUATION]
      = statement->quadratic[1];
  set_constant_coefficient (
      statement->constant[BS_SIG_D64_INVERSE_EQUATION], -1);
  spolymat_sort (statement->quadratic[1]);

  set_selector (statement->l2[0], BS_LAZER_SIG_D64_PREIMAGE_COLUMNS, 0);
  set_selector (statement->l2[1],
                BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_COLUMNS,
                BS_LAZER_SIG_D64_PREIMAGE_COLUMNS);
  set_selector (statement->l2[2], BS_LAZER_SIG_D64_RANDOMNESS_COLUMNS,
                BS_LAZER_SIG_D64_PREIMAGE_COLUMNS
                    + BS_LAZER_SIG_D64_FUNCTION_RANDOMNESS_COLUMNS);
  for (column = 0; column < BS_SIG_D64_L2_PROOFS; column++)
    statement->l2_ptrs[column] = statement->l2[column];

  polymat_alloc (statement->binary_m, blind_sig_sig_d64_ring, 1, 3);
  polymat_set_zero (statement->binary_m);
  set_identity_entry (statement->binary_m, 0, 0);

  polymat_alloc (statement->arp_s, blind_sig_sig_d64_ring, 1,
                 BS_LAZER_SIG_D64_BOUNDED_COLUMNS);
  polymat_set_zero (statement->arp_s);
}

void
bs_sig_d64_statement_clear (bs_sig_d64_statement *statement)
{
  unsigned int equation;

  for (equation = 0; equation < BS_SIG_D64_EQUATIONS; equation++)
    {
      spolyvec_free (statement->linear[equation]);
      poly_free (statement->constant[equation]);
    }
  spolymat_free (statement->quadratic[0]);
  spolymat_free (statement->quadratic[1]);
  for (equation = 0; equation < BS_SIG_D64_L2_PROOFS; equation++)
    polymat_free (statement->l2[equation]);
  polymat_free (statement->binary_m);
  polymat_free (statement->arp_s);
}
