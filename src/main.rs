//! Demo: evaluates both public functions. Toy parameters, not
//! cryptographically sized.

use blind_sig::binary_encoding::BinaryEncoding;
use blind_sig::hash_to_ring::HashToRing;
use qfall_math::integer::Z;
use qfall_tools::utils::common_moduli::new_anticyclic;

const D: i64 = 8;
const Q: u64 = 257;
const ROWS: i64 = 2;

fn main() {
    let modulus = new_anticyclic(D, Q).unwrap();
    println!("== blind-sig public-function demo (toy parameters) ==");
    println!("ring: R_q = Z_{Q}[X]/(X^{D} + 1), module rank n = {ROWS}\n");

    let hash_function = HashToRing::new(
        ROWS,
        1u64 << 10,
        1u64 << 20,
        1u64 << 10,
        modulus.clone(),
        "blind-sig-demo",
    );
    let key = hash_function.sample_key();
    println!("HashToRing: keyed and probabilistic, kappa = {key}");
    for _ in 0..3 {
        let input = hash_function.sample_input();
        let randomness = hash_function.sample_randomness();
        let value = hash_function.eval(&key, &input, &randomness);
        println!("  f(kappa, {input}, {randomness}) = {value}");
    }

    let binary_function = BinaryEncoding::new(ROWS, 10, modulus);
    println!(
        "\nBinaryEncoding: fixed function, input space [{}]",
        binary_function.input_space()
    );
    for input in [1u64, 2, 3] {
        let input = Z::from(input);
        println!("  f({input}) = {}", binary_function.eval(&input));
    }
}
