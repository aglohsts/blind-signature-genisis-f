//! Safe Rust boundary for the fixed LaZer `d = 64` profiles.
//! Report: "LaZer Integration".
//!
//! Two profiles are exposed. The linear profile proves the commitment
//! relation of `Pi_com`; the advanced profile proves the
//! final-signature relation of `Pi_sig`. Both are generated ahead of
//! time, so every dimension here is a compile-time constant and each
//! entry point checks its input lengths before it calls into C.

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;

/// The ring degree `d` shared by both profiles.
pub const DEGREE: usize = 64;

/// The modulus `q` shared by both profiles.
pub const MODULUS: u64 = 288_230_376_151_711_813;

/// The message and randomness bounds fixed by the generated profiles.
pub const PROFILE_MESSAGE_BOUND_SQ: i64 = 16;
pub const PROFILE_RANDOMNESS_BOUND_SQ: i64 = 2_000;
pub const PROFILE_FUNCTION_RANDOMNESS_BOUND_SQ: i64 = 2_000;
/// The squared preimage bound the final-signature profile proves. It
/// follows from the Gaussian width and the trapdoor dimensions, so a
/// key whose sampler is configured differently cannot use the profile.
pub const PROFILE_PREIMAGE_BOUND_SQ: i64 = 6_400_000;
pub const PROFILE_WITNESS_INF: i64 = 20;

// The commitment profile: [B_1 | B_2] * (m; r) - c = 0.
pub const COMMITMENT_COLUMNS: usize = 4;
pub const MATRIX_COEFFICIENTS: usize = COMMITMENT_COLUMNS * DEGREE;
pub const STATEMENT_COEFFICIENTS: usize = DEGREE;
pub const WITNESS_COEFFICIENTS: usize = COMMITMENT_COLUMNS * DEGREE;

// The final-signature profile. The bounded witness is (s, xi, r).
pub const PREIMAGE_COLUMNS: usize = 10;
pub const FUNCTION_RANDOMNESS_COLUMNS: usize = 2;
pub const RANDOMNESS_COLUMNS: usize = 2;
pub const BOUNDED_COLUMNS: usize =
    PREIMAGE_COLUMNS + FUNCTION_RANDOMNESS_COLUMNS + RANDOMNESS_COLUMNS;
pub const TAG_COEFFICIENTS: usize = DEGREE;
pub const LINEAR_COEFFICIENTS: usize = BOUNDED_COLUMNS * DEGREE;
pub const TAG_MATRIX_COEFFICIENTS: usize = DEGREE * TAG_COEFFICIENTS;
pub const OFFSET_COEFFICIENTS: usize = DEGREE;
pub const FINAL_WITNESS_COEFFICIENTS: usize = LINEAR_COEFFICIENTS;

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = -1;
const BUFFER_TOO_SMALL: i32 = -2;
const INTERNAL_ERROR: i32 = -3;

unsafe extern "C" {
    fn bs_lazer_init() -> i32;
    fn bs_lazer_d64_proof_len() -> usize;
    fn bs_lazer_d64_prove(
        a: *const i64,
        a_len: usize,
        c: *const i64,
        c_len: usize,
        w: *const i64,
        w_len: usize,
        ppseed: *const u8,
        coins: *const u8,
        proof: *mut u8,
        proof_capacity: usize,
        proof_len: *mut usize,
    ) -> i32;
    fn bs_lazer_d64_verify(
        a: *const i64,
        a_len: usize,
        c: *const i64,
        c_len: usize,
        ppseed: *const u8,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn bs_lazer_sig_d64_proof_capacity() -> usize;
    fn bs_lazer_sig_d64_proof_len() -> usize;
    fn bs_lazer_sig_d64_prove(
        linear: *const i64,
        linear_len: usize,
        tag_matrix: *const i64,
        tag_matrix_len: usize,
        offset: *const i64,
        offset_len: usize,
        witness: *const i64,
        witness_len: usize,
        tag: *const i64,
        tag_len: usize,
        ppseed: *const u8,
        coins: *const u8,
        proof: *mut u8,
        proof_capacity: usize,
        proof_len: *mut usize,
    ) -> i32;
    fn bs_lazer_sig_d64_verify(
        linear: *const i64,
        linear_len: usize,
        tag_matrix: *const i64,
        tag_matrix_len: usize,
        offset: *const i64,
        offset_len: usize,
        ppseed: *const u8,
        proof: *const u8,
        proof_len: usize,
    ) -> i32;
    fn lazer_get_version() -> *const c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidInput,
    ProfileMismatch(&'static str),
    CoefficientOutOfRange,
    BufferTooSmall,
    Internal,
    UnexpectedStatus(i32),
    InvalidVersionString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                name,
                expected,
                actual,
            } => write!(
                f,
                "invalid {name} length: expected {expected}, got {actual}"
            ),
            Self::InvalidInput => write!(f, "LaZer rejected the input or witness bounds"),
            Self::ProfileMismatch(reason) => write!(f, "LaZer profile mismatch: {reason}"),
            Self::CoefficientOutOfRange => write!(f, "a coefficient does not fit into i64"),
            Self::BufferTooSmall => write!(f, "LaZer proof output buffer was too small"),
            Self::Internal => write!(f, "LaZer reported an internal error"),
            Self::UnexpectedStatus(status) => write!(f, "unexpected LaZer status {status}"),
            Self::InvalidVersionString => write!(f, "LaZer returned an invalid version string"),
        }
    }
}

impl std::error::Error for Error {}

fn status_result(status: i32) -> Result<(), Error> {
    match status {
        OK => Ok(()),
        INVALID_ARGUMENT => Err(Error::InvalidInput),
        BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
        INTERNAL_ERROR => Err(Error::Internal),
        other => Err(Error::UnexpectedStatus(other)),
    }
}

fn require_len(name: &'static str, actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            name,
            expected,
            actual,
        })
    }
}

/// Initialises LaZer and returns the version reported by its C API.
pub fn version() -> Result<&'static str, Error> {
    // SAFETY: The shim initialises LaZer and owns the static version string.
    unsafe {
        status_result(bs_lazer_init())?;
        let ptr = lazer_get_version();
        if ptr.is_null() {
            return Err(Error::InvalidVersionString);
        }
        CStr::from_ptr(ptr)
            .to_str()
            .map_err(|_| Error::InvalidVersionString)
    }
}

/// Returns the fixed transport length of the commitment profile.
/// LaZer's variable-length encoding is followed by canonical zero
/// padding, so the proof size does not leak the witness.
pub fn proof_len() -> usize {
    // SAFETY: Reads a constant from the generated profile.
    unsafe { bs_lazer_d64_proof_len() }
}

/// Returns the guarded output capacity of the final-signature profile.
pub fn final_signature_proof_capacity() -> usize {
    // SAFETY: Reads constants from the generated profile and C shim.
    unsafe { bs_lazer_sig_d64_proof_capacity() }
}

/// Returns the expected encoded length of the final-signature profile.
pub fn final_signature_proof_len() -> usize {
    // SAFETY: Reads a constant from the generated profile.
    unsafe { bs_lazer_sig_d64_proof_len() }
}

/// Proves the fixed commitment relation. Pass `None` for system
/// randomness or a 32-byte `coins` value for deterministic tests.
pub fn prove(
    a: &[i64],
    c: &[i64],
    witness: &[i64],
    ppseed: &[u8; 32],
    coins: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    require_len("matrix", a.len(), MATRIX_COEFFICIENTS)?;
    require_len("statement", c.len(), STATEMENT_COEFFICIENTS)?;
    require_len("witness", witness.len(), WITNESS_COEFFICIENTS)?;

    let mut proof = vec![0; proof_len()];
    let mut written = 0;
    let coins_ptr = coins.map_or(std::ptr::null(), |value| value.as_ptr());
    // SAFETY: Lengths are checked above and the output buffer is allocated here.
    let status = unsafe {
        bs_lazer_d64_prove(
            a.as_ptr(),
            a.len(),
            c.as_ptr(),
            c.len(),
            witness.as_ptr(),
            witness.len(),
            ppseed.as_ptr(),
            coins_ptr,
            proof.as_mut_ptr(),
            proof.len(),
            &mut written,
        )
    };
    status_result(status)?;
    if written != proof.len() {
        return Err(Error::Internal);
    }
    Ok(proof)
}

/// Verifies a proof for the fixed commitment relation.
pub fn verify(a: &[i64], c: &[i64], ppseed: &[u8; 32], proof: &[u8]) -> Result<bool, Error> {
    require_len("matrix", a.len(), MATRIX_COEFFICIENTS)?;
    require_len("statement", c.len(), STATEMENT_COEFFICIENTS)?;
    if proof.len() != proof_len() {
        return Ok(false);
    }

    // SAFETY: Lengths are checked above, including the fixed proof size.
    let status = unsafe {
        bs_lazer_d64_verify(
            a.as_ptr(),
            a.len(),
            c.as_ptr(),
            c.len(),
            ppseed.as_ptr(),
            proof.as_ptr(),
            proof.len(),
        )
    };
    match status {
        1 => Ok(true),
        0 => Ok(false),
        other => {
            status_result(other)?;
            Err(Error::UnexpectedStatus(other))
        }
    }
}

/// Proves the fixed coefficient-level final-signature relation
/// `linear * (s, xi, r) + tag_matrix * enc(mu) + offset = 0`.
pub fn prove_final_signature(
    linear: &[i64],
    tag_matrix: &[i64],
    offset: &[i64],
    witness: &[i64],
    tag: &[i64],
    ppseed: &[u8; 32],
    coins: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    require_len(
        "final-signature linear matrix",
        linear.len(),
        LINEAR_COEFFICIENTS,
    )?;
    require_len(
        "final-signature tag matrix",
        tag_matrix.len(),
        TAG_MATRIX_COEFFICIENTS,
    )?;
    require_len("final-signature offset", offset.len(), OFFSET_COEFFICIENTS)?;
    require_len(
        "final-signature witness",
        witness.len(),
        FINAL_WITNESS_COEFFICIENTS,
    )?;
    require_len("final-signature tag", tag.len(), TAG_COEFFICIENTS)?;

    let mut proof = vec![0; final_signature_proof_capacity()];
    let mut written = 0;
    let coins_ptr = coins.map_or(std::ptr::null(), |value| value.as_ptr());
    // SAFETY: All input lengths and the owned output capacity are checked above.
    let status = unsafe {
        bs_lazer_sig_d64_prove(
            linear.as_ptr(),
            linear.len(),
            tag_matrix.as_ptr(),
            tag_matrix.len(),
            offset.as_ptr(),
            offset.len(),
            witness.as_ptr(),
            witness.len(),
            tag.as_ptr(),
            tag.len(),
            ppseed.as_ptr(),
            coins_ptr,
            proof.as_mut_ptr(),
            proof.len(),
            &mut written,
        )
    };
    status_result(status)?;
    if written == 0 || written > proof.len() {
        return Err(Error::Internal);
    }
    proof.truncate(written);
    Ok(proof)
}

/// Verifies a proof for the fixed final-signature relation.
pub fn verify_final_signature(
    linear: &[i64],
    tag_matrix: &[i64],
    offset: &[i64],
    ppseed: &[u8; 32],
    proof: &[u8],
) -> Result<bool, Error> {
    require_len(
        "final-signature linear matrix",
        linear.len(),
        LINEAR_COEFFICIENTS,
    )?;
    require_len(
        "final-signature tag matrix",
        tag_matrix.len(),
        TAG_MATRIX_COEFFICIENTS,
    )?;
    require_len("final-signature offset", offset.len(), OFFSET_COEFFICIENTS)?;
    if proof.is_empty() || proof.len() > final_signature_proof_capacity() {
        return Ok(false);
    }

    // SAFETY: Input lengths are checked above and the proof is read-only.
    let status = unsafe {
        bs_lazer_sig_d64_verify(
            linear.as_ptr(),
            linear.len(),
            tag_matrix.as_ptr(),
            tag_matrix.len(),
            offset.as_ptr(),
            offset.len(),
            ppseed.as_ptr(),
            proof.as_ptr(),
            proof.len(),
        )
    };
    match status {
        1 => Ok(true),
        0 => Ok(false),
        other => {
            status_result(other)?;
            Err(Error::UnexpectedStatus(other))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment_fixture() -> (Vec<i64>, Vec<i64>, Vec<i64>) {
        let mut a = vec![0; MATRIX_COEFFICIENTS];
        let mut c = vec![0; STATEMENT_COEFFICIENTS];
        let mut witness = vec![0; WITNESS_COEFFICIENTS];
        a[0] = 1;
        c[0] = 1;
        witness[0] = 1;
        (a, c, witness)
    }

    /// A minimal instance of the final-signature relation. The
    /// preimage block carries a non-zero entry so the norm equation
    /// has an inverse, and one tag bit is wired through the tag matrix.
    fn final_signature_fixture() -> (Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
        let mut linear = vec![0; LINEAR_COEFFICIENTS];
        let mut tag_matrix = vec![0; TAG_MATRIX_COEFFICIENTS];
        let mut offset = vec![0; OFFSET_COEFFICIENTS];
        let mut witness = vec![0; FINAL_WITNESS_COEFFICIENTS];
        let mut tag = vec![0; TAG_COEFFICIENTS];
        witness[63] = 2;
        linear[1] = 1;
        offset[0] = 2;
        tag[7] = 1;
        tag_matrix[3 * TAG_COEFFICIENTS + 7] = 5;
        offset[3] = -5;
        (linear, tag_matrix, offset, witness, tag)
    }

    /// Exercises the function-randomness block that the fixed-function
    /// profile did not have. Its columns start after the preimage.
    fn function_randomness_fixture() -> (Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
        let (mut linear, tag_matrix, mut offset, mut witness, tag) = final_signature_fixture();
        let xi_first = PREIMAGE_COLUMNS * DEGREE;
        witness[xi_first] = 3;
        linear[xi_first] = 1;
        offset[0] -= 3;
        (linear, tag_matrix, offset, witness, tag)
    }

    #[test]
    fn reports_expected_profile_sizes() {
        assert_eq!(proof_len(), 24_696);
        assert_eq!(final_signature_proof_len(), 25_296);
        assert_eq!(final_signature_proof_capacity(), 50_592);
    }

    #[test]
    fn reports_a_non_empty_version() {
        assert!(!version().expect("LaZer version").is_empty());
    }

    #[test]
    fn commitment_round_trip_and_rejections() {
        let (a, mut c, witness) = commitment_fixture();
        let ppseed = [7; 32];
        let coins = [9; 32];
        let mut proof = prove(&a, &c, &witness, &ppseed, Some(&coins)).expect("prove");

        assert!(verify(&a, &c, &ppseed, &proof).expect("verify"));
        c[0] = 2;
        assert!(!verify(&a, &c, &ppseed, &proof).expect("reject"));

        c[0] = 1;
        *proof.last_mut().expect("fixed proof buffer") = 1;
        assert!(!verify(&a, &c, &ppseed, &proof).expect("padding reject"));
    }

    #[test]
    fn rejects_commitment_witness_outside_profile() {
        let (a, c, mut witness) = commitment_fixture();
        witness[0] = 5;
        assert_eq!(
            prove(&a, &c, &witness, &[0; 32], Some(&[1; 32])),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn final_signature_round_trip_and_tampering_rejection() {
        let (linear, tag_matrix, mut offset, witness, tag) = final_signature_fixture();
        let ppseed = [7; 32];
        let coins = [9; 32];
        let mut proof = prove_final_signature(
            &linear,
            &tag_matrix,
            &offset,
            &witness,
            &tag,
            &ppseed,
            Some(&coins),
        )
        .expect("prove final signature");

        assert!(
            verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("verify final signature")
        );
        offset[0] += 1;
        assert!(
            !verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("reject changed statement")
        );
        offset[0] -= 1;
        proof[100] ^= 1;
        assert!(
            !verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("reject changed proof")
        );
        proof[100] ^= 1;
        proof.pop();
        assert!(
            !verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("reject shortened proof")
        );
    }

    /// The function-randomness block takes part in the equation and is
    /// covered by its own exact l2 proof.
    #[test]
    fn final_signature_covers_the_function_randomness_block() {
        let (linear, tag_matrix, offset, witness, tag) = function_randomness_fixture();
        let ppseed = [11; 32];
        let coins = [13; 32];
        let proof = prove_final_signature(
            &linear,
            &tag_matrix,
            &offset,
            &witness,
            &tag,
            &ppseed,
            Some(&coins),
        )
        .expect("prove final signature");
        assert!(
            verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("verify final signature")
        );
    }

    /// A function randomness above the profile bound is refused before
    /// LaZer is called.
    #[test]
    fn rejects_oversized_function_randomness() {
        let (linear, tag_matrix, offset, mut witness, tag) = function_randomness_fixture();
        witness[PREIMAGE_COLUMNS * DEGREE] = 1_000;
        assert_eq!(
            prove_final_signature(
                &linear,
                &tag_matrix,
                &offset,
                &witness,
                &tag,
                &[0; 32],
                Some(&[1; 32]),
            ),
            Err(Error::InvalidInput)
        );
    }

    /// A zero preimage has no modular inverse of its norm, so the
    /// non-zero requirement of R_sig is enforced.
    #[test]
    fn rejects_zero_preimage() {
        let (linear, tag_matrix, offset, mut witness, tag) = final_signature_fixture();
        witness[63] = 0;
        assert_eq!(
            prove_final_signature(
                &linear,
                &tag_matrix,
                &offset,
                &witness,
                &tag,
                &[0; 32],
                Some(&[1; 32]),
            ),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn rejects_non_binary_tag() {
        let (linear, tag_matrix, offset, witness, mut tag) = final_signature_fixture();
        tag[7] = 2;
        assert_eq!(
            prove_final_signature(
                &linear,
                &tag_matrix,
                &offset,
                &witness,
                &tag,
                &[0; 32],
                Some(&[1; 32]),
            ),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn both_profiles_round_trip_in_sequence() {
        let ppseed = [7; 32];
        let coins = [9; 32];
        let (a, c, witness) = commitment_fixture();
        let proof = prove(&a, &c, &witness, &ppseed, Some(&coins)).expect("prove");
        assert!(verify(&a, &c, &ppseed, &proof).expect("verify"));

        let (linear, tag_matrix, offset, witness, tag) = final_signature_fixture();
        let proof = prove_final_signature(
            &linear,
            &tag_matrix,
            &offset,
            &witness,
            &tag,
            &ppseed,
            Some(&coins),
        )
        .expect("prove final signature");
        assert!(
            verify_final_signature(&linear, &tag_matrix, &offset, &ppseed, &proof)
                .expect("verify final signature")
        );
    }
}
