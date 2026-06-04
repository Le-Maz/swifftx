//! SWIFFT and SWIFFTX hash function implementations.
//!
//! This library provides the core SWIFFT compression primitive and the full
//! SWIFFTX hash function, built upon finite field arithmetic over GF(257)
//! and leveraging portable SIMD operations for highly parallelizable performance.

#![feature(portable_simd)]

pub mod gf257;
pub mod swifft;
pub mod swifftx;

pub use swifftx::Swifftx;
