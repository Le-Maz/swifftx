#![feature(test)]

use swifftx::{Digest, Swifftx};
use test::{Bencher, black_box};

extern crate test;

#[bench]
fn full_swifftx(b: &mut Bencher) {
    let mut hasher = Swifftx::default();
    let data = b"test";
    let mut digest = Default::default();
    b.iter(|| {
        hasher.update(black_box(data));
        let _ = hasher.finalize_into_reset(&mut digest);
        black_box(digest);
    });
}
