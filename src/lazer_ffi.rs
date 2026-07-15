//! Safe Rust boundary for the fixed LaZer `d = 64` commitment proof profile.
//! Report: "LaZer Integration Feasibility".

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_char;

pub const DEGREE: usize = 64;
pub const COMMITMENT_COLUMNS: usize = 4;
pub const MATRIX_COEFFICIENTS: usize = COMMITMENT_COLUMNS * DEGREE;
pub const STATEMENT_COEFFICIENTS: usize = DEGREE;
pub const WITNESS_COEFFICIENTS: usize = COMMITMENT_COLUMNS * DEGREE;
pub const FINAL_PREIMAGE_COLUMNS: usize = 51;
pub const FINAL_RANDOMNESS_COLUMNS: usize = 2;
pub const FINAL_BOUNDED_COLUMNS: usize = FINAL_PREIMAGE_COLUMNS + FINAL_RANDOMNESS_COLUMNS;
pub const FINAL_TAG_COEFFICIENTS: usize = DEGREE;
pub const FINAL_LINEAR_COEFFICIENTS: usize = FINAL_BOUNDED_COLUMNS * DEGREE;
pub const FINAL_TAG_MATRIX_COEFFICIENTS: usize = DEGREE * FINAL_TAG_COEFFICIENTS;
pub const FINAL_OFFSET_COEFFICIENTS: usize = DEGREE;
pub const FINAL_WITNESS_COEFFICIENTS: usize = FINAL_LINEAR_COEFFICIENTS;

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

/// Returns the fixed transport length for the checked-in profile. LaZer's
/// variable-length encoding is followed by canonical zero padding.
pub fn proof_len() -> usize {
    // SAFETY: Reads a constant from the generated profile.
    unsafe { bs_lazer_d64_proof_len() }
}

/// Returns the guarded output capacity for the advanced signature profile.
pub fn final_signature_proof_capacity() -> usize {
    // SAFETY: Reads constants from the generated profile and C shim.
    unsafe { bs_lazer_sig_d64_proof_capacity() }
}

/// Proves the fixed coefficient-level final-signature relation.
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
        FINAL_LINEAR_COEFFICIENTS,
    )?;
    require_len(
        "final-signature tag matrix",
        tag_matrix.len(),
        FINAL_TAG_MATRIX_COEFFICIENTS,
    )?;
    require_len(
        "final-signature offset",
        offset.len(),
        FINAL_OFFSET_COEFFICIENTS,
    )?;
    require_len(
        "final-signature witness",
        witness.len(),
        FINAL_WITNESS_COEFFICIENTS,
    )?;
    require_len("final-signature tag", tag.len(), FINAL_TAG_COEFFICIENTS)?;

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

/// Verifies a proof for the fixed coefficient-level final-signature relation.
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
        FINAL_LINEAR_COEFFICIENTS,
    )?;
    require_len(
        "final-signature tag matrix",
        tag_matrix.len(),
        FINAL_TAG_MATRIX_COEFFICIENTS,
    )?;
    require_len(
        "final-signature offset",
        offset.len(),
        FINAL_OFFSET_COEFFICIENTS,
    )?;
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

/// Proves the fixed commitment relation. Pass `None` for system randomness or
/// a 32-byte `coins` value for deterministic tests and reproducible vectors.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_fixture() -> (Vec<i64>, Vec<i64>, Vec<i64>) {
        let mut a = vec![0; MATRIX_COEFFICIENTS];
        let mut c = vec![0; STATEMENT_COEFFICIENTS];
        let mut witness = vec![0; WITNESS_COEFFICIENTS];
        a[0] = 1;
        c[0] = 1;
        witness[0] = 1;
        (a, c, witness)
    }

    fn final_signature_fixture() -> (Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
        let mut linear = vec![0; FINAL_LINEAR_COEFFICIENTS];
        let mut tag_matrix = vec![0; FINAL_TAG_MATRIX_COEFFICIENTS];
        let mut offset = vec![0; FINAL_OFFSET_COEFFICIENTS];
        let mut witness = vec![0; FINAL_WITNESS_COEFFICIENTS];
        let mut tag = vec![0; FINAL_TAG_COEFFICIENTS];
        witness[63] = 2;
        linear[1] = 1;
        offset[0] = 2;
        tag[7] = 1;
        tag_matrix[3 * FINAL_TAG_COEFFICIENTS + 7] = 5;
        offset[3] = -5;
        (linear, tag_matrix, offset, witness, tag)
    }

    #[test]
    fn reports_expected_profile_size() {
        assert_eq!(proof_len(), 16_166);
    }

    #[test]
    fn reports_a_non_empty_version() {
        assert!(!version().expect("LaZer version").is_empty());
    }

    #[test]
    fn d64_proof_round_trip_and_wrong_statement_rejection() {
        let (a, mut c, witness) = identity_fixture();
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
    fn rejects_witness_outside_profile() {
        let (a, c, mut witness) = identity_fixture();
        witness[0] = 5;
        assert_eq!(
            prove(&a, &c, &witness, &[0; 32], Some(&[1; 32])),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn final_signature_proof_round_trip_and_tampering_rejection() {
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

        assert_eq!(final_signature_proof_capacity(), 63_172);
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

    #[test]
    fn profiles_round_trip_in_sequence() {
        let (a, mut c, witness) = identity_fixture();
        let ppseed = [7; 32];
        let coins = [9; 32];
        let mut proof = prove(&a, &c, &witness, &ppseed, Some(&coins)).expect("prove");
        assert!(verify(&a, &c, &ppseed, &proof).expect("verify"));
        c[0] = 2;
        assert!(!verify(&a, &c, &ppseed, &proof).expect("reject"));
        c[0] = 1;
        *proof.last_mut().expect("fixed proof buffer") = 1;
        assert!(!verify(&a, &c, &ppseed, &proof).expect("padding reject"));

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
