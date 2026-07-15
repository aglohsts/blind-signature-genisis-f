#include "shim_sig_statement.h"

#include <string.h>

#include "params_sig_d64.h"

/* Report: "The Final-Signature Proof". */

#define BS_SIG_D64_Q 281474976711349LL

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

void
bs_sig_d64_statement_init (bs_sig_d64_statement *statement,
                           const int64_t *linear,
                           const int64_t *tag_matrix,
                           const int64_t *offset)
{
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
}
