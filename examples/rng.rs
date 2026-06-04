//! Generates a continuous stream of pseudorandom bytes using SwifftX for rngtest.

use digest::Digest;
use rand::{Rng, rngs::ThreadRng};
use std::io::{self, Write};
use swifftx::Swifftx;

fn main() -> io::Result<()> {
    let mut rng = ThreadRng::default();
    let seed = rng.next_u64();

    let mut stdout = io::stdout().lock();
    let mut counter: u64 = 0;
    let mut hasher = Swifftx::new();
    let mut block = Default::default();

    loop {
        hasher.update(&seed.to_le_bytes());
        hasher.update(&counter.to_le_bytes());

        hasher.finalize_into_reset(&mut block);

        if stdout.write_all(&block).is_err() {
            break;
        }

        counter = counter.wrapping_add(1);
    }

    Ok(())
}
