#include "shim.h"

/* Report: "The Final-Signature Proof". */

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
