//! Demo: evaluates the two tag functions on a few tags. Toy
//! parameters, not cryptographically sized.

use blind_sig::tag_function::{BinaryEncoding, HashToRing, TagFunction};
use qfall_math::integer::Z;
use qfall_tools::utils::common_moduli::new_anticyclic;

fn main() {
    let d = 8;
    let q = 257;
    let n = 2;
    let modulus = new_anticyclic(d, q).unwrap();

    println!("== blind-sig tag-function demo (toy parameters) ==");
    println!("ring: R_q = Z_{q}[X]/(X^{d} + 1), module rank n = {n}\n");

    let f_bin = BinaryEncoding::new(n, 10, modulus.clone());
    println!(
        "BinaryEncoding (BLNS Sec. 3.1.2), N = 2^10 = {}",
        f_bin.domain_size()
    );
    for x in [1u64, 2, 3] {
        println!("  f({x}) = {}", f_bin.eval(&Z::from(x)));
    }

    let f_hash = HashToRing::new(n, 1u64 << 20, modulus, "blind-sig-demo");
    println!(
        "\nHashToRing (random-oracle style), N = 2^20 = {}",
        f_hash.domain_size()
    );
    for x in [1u64, 2, 3] {
        println!("  f({x}) = {}", f_hash.eval(&Z::from(x)));
    }
}
