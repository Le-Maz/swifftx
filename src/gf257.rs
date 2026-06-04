//! Defines the finite field GF(257) and its basic arithmetic operations.

use rustcrypto_ff::PrimeField;

/// Represents an element in the prime field GF(257).
#[derive(PrimeField)]
#[PrimeFieldModulus = "257"]
#[PrimeFieldGenerator = "3"]
#[PrimeFieldReprEndianness = "little"]
pub struct Gf257([u64; 1]);

impl Gf257 {
    /// Creates a new [`Gf257`] element from a 64-bit unsigned integer, reducing it modulo 257.
    pub const fn from_u64(x: u64) -> Self {
        Self([x % 257])
    }

    /// Returns the underlying 64-bit integer representation of the field element.
    pub const fn to_u64(self) -> u64 {
        self.0[0]
    }

    /// Multiplies two [`Gf257`] elements together, returning the result modulo 257.
    pub const fn const_mul(self, other: Self) -> Self {
        Self::from_u64(self.to_u64() * other.to_u64())
    }
}
