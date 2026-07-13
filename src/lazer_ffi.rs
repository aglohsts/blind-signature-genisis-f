//! Minimal Rust binding for the optional LaZer C ABI.
//! Report: "LaZer Integration Feasibility".

use std::ffi::CStr;
use std::os::raw::c_char;

unsafe extern "C" {
    fn lazer_init();
    fn lazer_get_version() -> *const c_char;
}

/// Initialises LaZer and returns the version reported by its C API.
pub fn version() -> Result<&'static str, &'static str> {
    // SAFETY: Both calls borrow no data; LaZer owns the static string.
    let version = unsafe {
        lazer_init();
        let ptr = lazer_get_version();
        if ptr.is_null() {
            return Err("LaZer returned a null version string");
        }
        CStr::from_ptr(ptr)
    };

    version
        .to_str()
        .map_err(|_| "LaZer returned a non-UTF-8 version string")
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_a_non_empty_version() {
        assert!(!super::version().expect("LaZer version").is_empty());
    }
}
