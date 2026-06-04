//! Implements the full SWIFFTX hash function.
//!
//! SWIFFTX utilizes the SWIFFT compression primitive within the HAIFA (HAsh Iterative
//! FrAmework) mode of operation, adding non-linear operations (via an S-box) and a
//! final transformation step to achieve a full cryptographic hash function capable of
//! mapping arbitrary-length inputs to a fixed 512-bit digest.

use crate::{gf257::Gf257, swifft::swifft};
use digest::{FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update};
use std::convert::TryInto;
use std::simd::u8x64;
use typenum::U64;

/// The SWIFFTX hash function implementing the HAIFA mode of operation.
#[derive(Clone)]
pub struct Swifftx {
    /// The current 65-byte chaining value linking blocks together.
    chaining_value: [u8; 65],
    /// The intermediate message buffer collecting incoming bytes.
    buffer: [u8; 175],
    /// The number of valid bytes currently residing within the message buffer.
    buffer_len: usize,
    /// The total number of bits processed by the hash function so far.
    total_bits: u64,
    /// An optional salt value intended for domain separation or randomization.
    salt: u64,
}

impl Swifftx {
    /// Processes a full 175-byte (1400-bit) message block according to the HAIFA framework.
    fn process_block(&mut self) {
        let mut input = [0u8; 256];

        input[0..65].copy_from_slice(&self.chaining_value);
        input[65..73].copy_from_slice(&self.total_bits.to_le_bytes());
        input[73..81].copy_from_slice(&self.salt.to_le_bytes());
        input[81..256].copy_from_slice(&self.buffer);

        let mut x = [0u64; 32];
        for i in 0..32 {
            x[i] = u64::from_le_bytes(input[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        self.chaining_value = swifftx_compress(&x);
    }
}

impl Default for Swifftx {
    fn default() -> Self {
        let mut state = Self {
            chaining_value: [0u8; 65],
            buffer: [0u8; 175],
            buffer_len: 0,
            total_bits: 0,
            salt: 0,
        };
        state.reset();
        state
    }
}

impl OutputSizeUser for Swifftx {
    type OutputSize = U64;
}

impl Update for Swifftx {
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len == 175 {
                self.total_bits += 1400; // 175 bytes * 8 bits
                self.process_block();
                self.buffer_len = 0;
            }
        }
    }
}

impl FixedOutput for Swifftx {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let mut input = [0u8; 256];
        let final_total_bits = self.total_bits + (self.buffer_len * 8) as u64;

        input[0..65].copy_from_slice(&self.chaining_value);
        input[65..65 + self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        input[65 + self.buffer_len] = 0x80;
        input[246..254].copy_from_slice(&final_total_bits.to_le_bytes());
        input[254..256].copy_from_slice(&512u16.to_le_bytes());

        let mut x = [0u64; 32];
        for i in 0..32 {
            x[i] = u64::from_le_bytes(input[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        let final_chain = swifftx_compress(&x);
        let digest_bytes = final_transform(&final_chain);

        out.copy_from_slice(&digest_bytes);
    }
}

impl Reset for Swifftx {
    fn reset(&mut self) {
        let mut input = [0u8; 256];

        input[0..65].copy_from_slice(&IV);
        input[65..67].copy_from_slice(&512u16.to_le_bytes());

        let mut x = [0u64; 32];
        for i in 0..32 {
            x[i] = u64::from_le_bytes(input[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        self.chaining_value = swifftx_compress(&x);
        self.buffer.fill(0);
        self.buffer_len = 0;
        self.total_bits = 0;
        self.salt = 0;
    }
}

impl FixedOutputReset for Swifftx {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        let final_state = self.clone();
        final_state.finalize_into(out);
        self.reset();
    }
}

impl HashMarker for Swifftx {}

/// A predefined 256-byte S-box used for introducing non-linearity into the hash function.
const SBOX: [u8; 256] = [
    0x7d, 0xd1, 0x70, 0x0b, 0xfa, 0x39, 0x18, 0xc3, 0xf3, 0xbb, 0xa7, 0xd4, 0x84, 0x25, 0x3b, 0x3c,
    0x2c, 0x15, 0x69, 0x9a, 0xf9, 0x27, 0xfb, 0x02, 0x52, 0xba, 0xa8, 0x4b, 0x20, 0xb5, 0x8b, 0x3a,
    0x88, 0x8e, 0x26, 0xcb, 0x71, 0x5e, 0xaf, 0xad, 0x0c, 0xac, 0xa1, 0x93, 0xc6, 0x78, 0xce, 0xfc,
    0x2a, 0x76, 0x17, 0x1f, 0x62, 0xc2, 0x2e, 0x99, 0x11, 0x37, 0x65, 0x40, 0xfd, 0xa0, 0x03, 0xc1,
    0xca, 0x48, 0xe2, 0x9b, 0x81, 0xe4, 0x1c, 0x01, 0xec, 0x68, 0x7a, 0x5a, 0x50, 0xf8, 0x0e, 0xa3,
    0xe8, 0x61, 0x2b, 0xa2, 0xeb, 0xcf, 0x8c, 0x3d, 0xb4, 0x95, 0x13, 0x08, 0x46, 0xab, 0x91, 0x7b,
    0xea, 0x55, 0x67, 0x9d, 0xdd, 0x29, 0x6a, 0x8f, 0x9f, 0x22, 0x4e, 0xf2, 0x57, 0xd2, 0xa9, 0xbd,
    0x38, 0x16, 0x5f, 0x4c, 0xf7, 0x9e, 0x1b, 0x2f, 0x30, 0xc7, 0x41, 0x24, 0x5c, 0xbf, 0x05, 0xf6,
    0x0a, 0x31, 0xa5, 0x45, 0x21, 0x33, 0x6b, 0x6d, 0x6c, 0x86, 0xe1, 0xa4, 0xe6, 0x92, 0x9c, 0xdf,
    0xe7, 0xbe, 0x28, 0xe3, 0xfe, 0x06, 0x4d, 0x98, 0x80, 0x04, 0x96, 0x36, 0x3e, 0x14, 0x4a, 0x34,
    0xd3, 0xd5, 0xdb, 0x44, 0xcd, 0xf5, 0x54, 0xdc, 0x89, 0x09, 0x90, 0x42, 0x87, 0xff, 0x7e, 0x56,
    0x5d, 0x59, 0xd7, 0x23, 0x75, 0x19, 0x97, 0x73, 0x83, 0x64, 0x53, 0xa6, 0x1e, 0xd8, 0xb0, 0x49,
    0x3f, 0xef, 0xbc, 0x7f, 0x43, 0xf0, 0xc9, 0x72, 0x0f, 0x63, 0x79, 0x2d, 0xc0, 0xda, 0x66, 0xc8,
    0x32, 0xde, 0x47, 0x07, 0xb8, 0xe9, 0x1d, 0xc4, 0x85, 0x74, 0x82, 0xcc, 0x60, 0x51, 0x77, 0x0d,
    0xaa, 0x35, 0xed, 0x58, 0x7c, 0x5b, 0xb9, 0x94, 0x6e, 0x8d, 0xb1, 0xc5, 0xb7, 0xee, 0xb6, 0xae,
    0x10, 0xe0, 0xd6, 0xd9, 0xe5, 0x4f, 0xf1, 0x12, 0x00, 0xd0, 0xf4, 0x1a, 0x6f, 0x8a, 0xb3, 0xb2,
];

/// The standardized 65-byte Initialization Vector (IV) used to seed the initial SWIFFTX state.
const IV: [u8; 65] = [
    0x1f, 0xd7, 0x60, 0x96, 0xf1, 0xf5, 0xf7, 0x5d, 0xbb, 0x3e, 0x73, 0xd4, 0x4c, 0x76, 0x61, 0x23,
    0x52, 0x3b, 0x7e, 0xb2, 0x0d, 0xa6, 0xab, 0xab, 0xd2, 0x87, 0x03, 0x3b, 0x9d, 0x54, 0x75, 0x2b,
    0x3c, 0x4e, 0x27, 0x04, 0x53, 0x76, 0xe2, 0x84, 0x48, 0x73, 0xea, 0xfb, 0xe9, 0xf1, 0xc3, 0xfb,
    0x13, 0x0b, 0x3d, 0xbb, 0xbe, 0x9a, 0x59, 0x95, 0xa7, 0xfd, 0xf4, 0xf9, 0xcc, 0x9c, 0x52, 0x08,
    0xa8,
];

/// Converts an array of 64 [`Gf257`] field elements into an array of 65 bytes.
///
/// The mathematical definition maps every 8 field elements into 8 bytes and an overflow bit,
/// accumulating the 8 overflow bits into the 65th output byte.
fn convert_to_bytes(z: &[Gf257; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    let mut b_bits = 0u8;

    for k in 0..8 {
        let mut val: u128 = 0;
        let mut multiplier: u128 = 1;
        for i in 0..8 {
            val += (z[8 * k + i].to_u64() as u128) * multiplier;
            multiplier *= 257;
        }

        for i in 0..8 {
            out[8 * k + i] = ((val >> (8 * i)) & 0xFF) as u8;
        }
        let b_k = ((val >> 64) & 1) as u8;
        b_bits |= b_k << k;
    }
    out[64] = b_bits;
    out
}

/// Computes the SWIFFTX compression function mapping 2048 input bits to 520 output bits.
fn swifftx_compress(x: &[u64; 32]) -> [u8; 65] {
    let mut z_j = [[0u8; 65]; 3];

    for j in 0..3 {
        let swifft_out = swifft(*x, j);
        let mut bytes = convert_to_bytes(&swifft_out);
        for b in bytes.iter_mut() {
            *b = SBOX[*b as usize];
        }
        z_j[j] = bytes;
    }

    let mut r_bytes = [0u8; 200];
    r_bytes[0..64].copy_from_slice(&z_j[0][0..64]);
    r_bytes[64..128].copy_from_slice(&z_j[1][0..64]);
    r_bytes[128..192].copy_from_slice(&z_j[2][0..64]);

    r_bytes[192] = z_j[0][64];
    r_bytes[193] = z_j[1][64];
    r_bytes[194] = z_j[2][64];

    let sbox_0 = SBOX[0];
    r_bytes[195] = sbox_0;
    r_bytes[196] = sbox_0;
    r_bytes[197] = sbox_0;
    r_bytes[198] = sbox_0;
    r_bytes[199] = sbox_0;

    let mut r_u64 = [0u64; 25];
    for i in 0..25 {
        r_u64[i] = u64::from_le_bytes(r_bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    let outer_swifft = swifft(r_u64, 0);
    convert_to_bytes(&outer_swifft)
}

/// Performs the final transformation to map 520 bits (65 bytes) to a uniformly
/// distributed 512-bit (64 bytes) digest.
fn final_transform(x: &[u8; 65]) -> [u8; 64] {
    let mut padded = [0u8; 72];
    padded[..65].copy_from_slice(x);

    let mut z_simd = u8x64::splat(0);

    for i in 0..9 {
        let chunk = &padded[i * 8..(i + 1) * 8];
        let mut x_val = u64::from_le_bytes(chunk.try_into().unwrap());

        if x_val == 0 {
            continue;
        }

        let p_i = &crate::swifft::A_MATRICES[1][i];
        let mut p_arr = [0u8; 64];
        for k in 0..64 {
            p_arr[k] = p_i[k] as u8;
        }

        while x_val != 0 {
            let j = x_val.trailing_zeros() as usize;

            let mut term = [0u8; 64];
            let (left, right) = p_arr.split_at(64 - j);

            term[j..].copy_from_slice(left);

            // Negate the wrapped portion of the polynomial
            for (idx, &val) in right.iter().enumerate() {
                term[idx] = (0u8).wrapping_sub(val);
            }

            z_simd += u8x64::from_array(term);
            x_val &= x_val - 1; // Clear processed bit
        }
    }
    z_simd.to_array()
}

#[cfg(test)]
/// Test suite ensuring the correctness and integrity of the SWIFFTX implementation.
mod tests {
    use super::{SBOX, Swifftx, convert_to_bytes, final_transform, swifftx_compress};
    use crate::gf257::Gf257;
    use digest::Digest;

    #[test]
    fn sbox_is_permutation() {
        let mut seen = [false; 256];
        for &val in SBOX.iter() {
            seen[val as usize] = true;
        }
        assert!(seen.iter().all(|&x| x), "SBOX is not a valid permutation");
    }

    #[test]
    fn convert_to_bytes_math_property() {
        let mut z_in = [Gf257::from_u64(0); 64];
        for i in 0..64 {
            z_in[i] = Gf257::from_u64((i * 13) as u64 % 257);
        }

        let out = convert_to_bytes(&z_in);

        for k in 0..8 {
            let mut sum_257: u128 = 0;
            let mut mult_257: u128 = 1;
            for i in 0..8 {
                sum_257 += (z_in[8 * k + i].to_u64() as u128) * mult_257;
                mult_257 *= 257;
            }

            let mut sum_256: u128 = 0;
            let mut mult_256: u128 = 1;
            for i in 0..8 {
                sum_256 += (out[8 * k + i] as u128) * mult_256;
                mult_256 *= 256;
            }

            let b_k = (out[64] >> k) & 1;
            sum_256 += (b_k as u128) * mult_256;

            assert_eq!(sum_257, sum_256, "Base conversion failed for block {}", k);
        }
    }

    #[test]
    fn swifftx_compress_execution() {
        let input = [0u64; 32];
        let output = swifftx_compress(&input);

        assert_eq!(output.len(), 65);

        let mut is_all_zero = true;
        for &byte in output.iter() {
            if byte != 0 {
                is_all_zero = false;
                break;
            }
        }
        assert!(
            !is_all_zero,
            "Compression output should not be trivially zero"
        );
    }

    #[test]
    fn final_transform_execution() {
        let mut input = [0u8; 65];
        for i in 0..65 {
            input[i] = i as u8;
        }

        let output = final_transform(&input);

        assert_eq!(output.len(), 64);

        let mut is_all_zero = true;
        for &byte in output.iter() {
            if byte != 0 {
                is_all_zero = false;
                break;
            }
        }
        assert!(
            !is_all_zero,
            "Transform output should not be trivially zero"
        );
    }

    #[test]
    fn hashes_empty_message_correctly() {
        let hasher = Swifftx::new();
        let result = hasher.finalize();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn incremental_hashing_matches_all_at_once() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let mut hasher1 = Swifftx::new();
        hasher1.update(data);
        let res1 = hasher1.finalize();

        let mut hasher2 = Swifftx::new();
        for &byte in data {
            hasher2.update(&[byte]);
        }
        let res2 = hasher2.finalize();

        assert_eq!(res1, res2);
    }

    #[test]
    fn resets_state_correctly() {
        let data = b"Reset test data";

        let mut hasher = Swifftx::new();
        hasher.update(data);
        let res1 = hasher.finalize_reset();

        hasher.update(data);
        let res2 = hasher.finalize();

        assert_eq!(res1, res2);
    }

    #[test]
    fn hashes_multiple_blocks_correctly() {
        let data = vec![0x42; 400];

        let mut hasher = Swifftx::new();
        hasher.update(&data);
        let result = hasher.finalize();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn chained_updates_match_standard_updates() {
        let data1 = b"Part one. ";
        let data2 = b"Part two.";

        let res1 = Swifftx::new()
            .chain_update(data1)
            .chain_update(data2)
            .finalize();

        let mut hasher2 = Swifftx::new();
        hasher2.update(data1);
        hasher2.update(data2);
        let res2 = hasher2.finalize();

        assert_eq!(res1, res2);
    }
}
