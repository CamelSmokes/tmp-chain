use crate::{Error, Hash};

use ahashfunction::ahashfunction::ahashfunction_hash;

// // These are tweakable parameters
// pub const MEMORY_SIZE: usize = 32768;
// pub const SCRATCHPAD_ITERS: usize = 5000;
// pub const ITERS: usize = 1;
// pub const BUFFER_SIZE: usize = 42;
// pub const SLOT_LENGTH: usize = 256;

// // Untweakable parameters
// pub const KECCAK_WORDS: usize = 25;
pub const BYTES_ARRAY_INPUT: usize = 200;
// pub const STAGE_1_MAX: usize = MEMORY_SIZE / KECCAK_WORDS;

// // Scratchpad used to store intermediate values
// // It has a fixed size of `MEMORY_SIZE` u64s
// // It can be easily reused for multiple hashing operations safely
// #[derive(Debug, Clone)]
// pub struct ScratchPad([u64; MEMORY_SIZE]);

// impl ScratchPad {
//     pub fn len(&self) -> usize {
//         self.0.len()
//     }

//     pub fn as_mut_slice(&mut self) -> &mut [u64; MEMORY_SIZE] {
//         &mut self.0
//     }
// }

// impl Default for ScratchPad {
//     fn default() -> Self {
//         Self([0; MEMORY_SIZE])
//     }
// }

// Align the input to 8 bytes
const ALIGNMENT: usize = 8;

#[derive(Debug, bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct Bytes8Alignment([u8; ALIGNMENT]);

// // This is a workaround to force the correct alignment on Windows and MacOS
// // We need an input of `BYTES_ARRAY_INPUT` bytes, but we need to ensure that it's aligned to 8 bytes
// // to be able to cast it to a `[u64; KECCAK_WORDS]` later on.
#[derive(Debug, Clone)]
pub struct AlignedInput {
    data: Vec<Bytes8Alignment>,
}

impl Default for AlignedInput {
    fn default() -> Self {
        let mut n = BYTES_ARRAY_INPUT / ALIGNMENT;
        if BYTES_ARRAY_INPUT % ALIGNMENT != 0 {
            n += 1;
        }

        Self {
            data: vec![Bytes8Alignment([0; ALIGNMENT]); n],
        }
    }
}

impl AlignedInput {
    // The number of elements in the input
    pub fn len(&self) -> usize {
        self.data.len()
    }

    // The size of the input in bytes
    pub fn size(&self) -> usize {
        self.data.len() * ALIGNMENT
    }

    // Get a mutable pointer to the input
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }

    // Retrieve the input as a mutable slice
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8; BYTES_ARRAY_INPUT], Error> {
        bytemuck::cast_slice_mut(&mut self.data)
            .try_into()
            .map_err(|_| Error::FormatError)
    }

    // Retrieve the input as a slice
    pub fn as_slice(&self) -> Result<&[u8; BYTES_ARRAY_INPUT], Error> {
        bytemuck::cast_slice(&self.data)
            .try_into()
            .map_err(|_| Error::FormatError)
    }
}

pub fn vyridium_hash(input: &[u8; BYTES_ARRAY_INPUT]) -> Result<Hash, Error> {
    let hash = ahashfunction_hash(input);

    Ok(hash)
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::{hint, time::Instant};

//     #[test]
//     fn benchmark_cpu_hash() {
//         const ITERATIONS: u32 = 1000;
//         let mut input = [0u8; 200];
//         let mut scratch_pad = ScratchPad::default();

//         let start = Instant::now();
//         for i in 0..ITERATIONS {
//             input[0] = i as u8;
//             input[1] = (i >> 8) as u8;
//             let _ = hint::black_box(vyridium_hash(&mut input, &mut scratch_pad)).unwrap();
//         }

//         let elapsed = start.elapsed();
//         println!("Time took: {:?}", elapsed);
//         println!(
//             "H/s: {:.2}",
//             (ITERATIONS as f64 * 1000.) / (elapsed.as_millis() as f64)
//         );
//         println!(
//             "ms per hash: {:.3}",
//             (elapsed.as_millis() as f64) / ITERATIONS as f64
//         );
//     }
// }
