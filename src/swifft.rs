//! Implements the core SWIFFT function, a highly parallelizable, lattice-based compression primitive.
//!
//! SWIFFT utilizes the Fast Fourier Transform (FFT) over the finite field GF(257). It provides
//! asymptotic security proofs against collision-finding under worst-case assumptions about ideal
//! lattices. Because SWIFFT is inherently linear, it is typically deployed as an inner layer
//! building block for larger, non-linear cryptographic constructs (such as SWIFFTX) rather than
//! a standalone general-purpose hash function.

use crate::gf257::Gf257;
use std::simd::Simd;
use std::simd::u32x64;

/// A primitive 128th root of unity in $GF(257)$.
const OMEGA: Gf257 = Gf257::from_u64(42);
/// The square of the primitive root of unity, used for evaluating polynomials.
const OMEGA_SQ: Gf257 = OMEGA.const_mul(OMEGA);
/// The modulus used for reducing values to $GF(257)$.
const MOD257: Simd<u32, 64> = u32x64::splat(257);

/// Raw ASCII digits of pi used as a nothing-up-my-sleeve number for matrix generation.
const PI_DIGITS: &[u8] = include_bytes!("pi_digits.txt");

/// Deterministically compiles the A0, A1, and A2 randomizer parameter matrices.
/// Size: 3 matrices, each containing up to 32 tracks by 64 structural output components.
pub(crate) const A_MATRICES: [[u32x64; 32]; 3] = const {
    let mut matrices = [[u32x64::splat(0); 32]; 3];
    let mut temp_a = [0u16; 6144];
    let mut ca = 0;
    let mut cp = 0;

    let mut pi_parsed = [0u8; 25000];
    let mut parse_idx = 0;

    while parse_idx < 25000 && parse_idx < PI_DIGITS.len() {
        pi_parsed[parse_idx] = PI_DIGITS[parse_idx] - b'0';
        parse_idx += 1;
    }

    while ca < 6144 && (cp + 2) < pi_parsed.len() {
        let d0 = pi_parsed[cp] as u16;
        let d1 = pi_parsed[cp + 1] as u16;
        let d2 = pi_parsed[cp + 2] as u16;

        let eta = d0 * 100 + d1 * 10 + d2;

        if eta < 257 * 3 {
            temp_a[ca] = eta % 257;
            ca += 1;
        }
        cp += 3;
    }

    let mut k = 0;
    while k < 3 {
        let mut i = 0;
        while i < 32 {
            let mut j = 0;
            while j < 64 {
                let val = temp_a[2048 * k + 64 * i + j];
                matrices[k][i].as_mut_array()[j] = val as u32;
                j += 1;
            }
            i += 1;
        }
        k += 1;
    }

    matrices
};

/// Precomputed polynomial evaluation weight matrix for the Fourier transform components.
/// Maps each bit position of the input to its evaluated value at the 64 roots of unity.
const W_MATRIX: [u32x64; 64] = const {
    let mut w = [u32x64::splat(0); 64];
    let mut k = 0;
    while k < 64 {
        let mut j = 0;
        let mut omega_pow_2jp1 = OMEGA;
        while j < 64 {
            let mut res = Gf257::from_u64(1);
            let mut base = omega_pow_2jp1;
            let mut exp = k;
            while exp > 0 {
                if exp % 2 == 1 {
                    res = res.const_mul(base);
                }
                base = base.const_mul(base);
                exp /= 2;
            }
            w[k].as_mut_array()[j] = res.to_u64() as u32;

            omega_pow_2jp1 = omega_pow_2jp1.const_mul(OMEGA_SQ);
            j += 1;
        }
        k += 1;
    }
    w
};

/// Reverses the lowest 6 bits of a given integer.
///
/// Used to calculate the target positions of bits during the index bit-reversal
/// permutation required by the Fast Fourier Transform structure.
const fn rev_6bit(x: usize) -> usize {
    let mut reversed = 0;
    let mut i = 0;
    while i < 6 {
        if (x & (1 << i)) != 0 {
            reversed |= 1 << (5 - i);
        }
        i += 1;
    }
    reversed
}

/// Permutes the bits of a 64-bit integer based on a 6-bit block reversal strategy.
///
/// Each of the 64 bits is relocated to a new position determined by the bit-reversed
/// value of its original 6-bit index.
const fn index_bit_reversal(x: u64) -> u64 {
    let mut x_prime = 0;
    let mut i = 0;
    while i < 64 {
        let j = rev_6bit(i);
        x_prime |= ((x >> j) & 1) << i;
        i += 1;
    }
    x_prime
}

/// Computes the core SWIFFT transformation on an array of 64-bit blocks.
///
/// This function performs a lattice-based compression operation by treating the bits
/// of the input integers as coefficients of polynomials. It transforms these polynomials
/// into the Fourier domain over the finite field $GF(257)$, evaluates them at specific
/// roots of unity, and multiplies the results by a deterministically generated constant
/// matrix `A` to achieve mixing and compression.
///
/// # Arguments
///
/// * `xs` - An array of `M` 64-bit integers representing the input message blocks.
/// * `a_idx` - The index (`0`, `1`, or `2`) specifying which of the constant `A` matrices to use.
///
/// # Returns
///
/// Returns a fully mixed array of `64` [`Gf257`] field elements representing the hash output.
pub fn swifft<const M: usize>(mut xs: [u64; M], a_idx: usize) -> [Gf257; 64] {
    let mut i = 0;
    while i < M {
        xs[i] = index_bit_reversal(xs[i]);
        i += 1;
    }

    let mut zs_simd = u32x64::splat(0);

    let mut i = 0;
    while i < M {
        let mut eval_res = u32x64::splat(0);
        let mut x_val = xs[i];

        // Evaluate polynomial across all 64 paths simultaneously matching set bits.
        while x_val != 0 {
            let trailing = x_val.trailing_zeros() as usize;
            eval_res += W_MATRIX[trailing];
            x_val &= x_val - 1; // Clear the processed bit
        }

        let a_row = A_MATRICES[a_idx][i];
        zs_simd = zs_simd + eval_res * a_row;

        i += 1;
    }

    // Delay the modulo reduction until all terms for the block are summed.
    zs_simd %= MOD257;

    let mut zs = [Gf257::from_u64(0); 64];
    let zs_arr = zs_simd.to_array();

    let mut j = 0;
    while j < 64 {
        zs[j] = Gf257::from_u64(zs_arr[j] as u64);
        j += 1;
    }

    zs
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, rngs::ThreadRng};

    /// Validates the linear homomorphic property of the SWIFFT compression function over Z_257.
    ///
    /// By mathematical definition, the integer addition of two binary variables relates to
    /// bitwise operations via `X + Y = (X ^ Y) + 2(X & Y)`. Because SWIFFT is a linear
    /// homomorphism, this property maps to the outputs as:
    /// `SWIFFT(X) + SWIFFT(Y) = SWIFFT(X ^ Y) + 2 * SWIFFT(X & Y) (mod 257)`.
    #[test]
    fn swifft_is_linear() {
        let mut rng = ThreadRng::default();
        let mut xs1 = [0u64; 32];
        let mut xs2 = [0u64; 32];
        let mut xs_xor = [0u64; 32];
        let mut xs_and = [0u64; 32];

        let mut i = 0;
        while i < 32 {
            xs1[i] = rng.next_u64();
            xs2[i] = rng.next_u64();

            xs_xor[i] = xs1[i] ^ xs2[i];
            xs_and[i] = xs1[i] & xs2[i];
            i += 1;
        }

        let zs1 = swifft(xs1, 0);
        let zs2 = swifft(xs2, 0);
        let zs_xor = swifft(xs_xor, 0);
        let zs_and = swifft(xs_and, 0);

        let two = Gf257::from_u64(2);

        let mut j = 0;
        while j < 64 {
            let right_side = zs1[j] + zs2[j];

            let overlap_doubled = two * zs_and[j];
            let left_side = zs_xor[j] + overlap_doubled;

            assert_eq!(left_side, right_side);
            j += 1;
        }
    }
}
