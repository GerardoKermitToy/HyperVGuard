// Windows x64's compiler/ABI preserves SSE state; SSE2 is baseline on x64.
// Only integer SSE2 instructions are used: no x87, AVX, runtime feature probe,
// or explicit extended-state save/restore. See Microsoft's x64 WDM guidance:
// https://learn.microsoft.com/windows-hardware/drivers/kernel/using-floating-point-or-mmx-in-a-wdm-driver
#[cfg(target_arch = "x86_64")]
mod implementation {
    use core::arch::x86_64::{
        __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8,
    };

    pub const WIDTH: usize = 16;
    pub struct Group(__m128i);
    impl Group {
        // Caller owns WIDTH initialized control bytes starting at data.
        #[inline]
        pub unsafe fn load(data: *const u8) -> Self {
            Self(unsafe { _mm_loadu_si128(data.cast()) })
        }
        #[inline]
        pub fn matches(&self, byte: u8) -> u32 {
            unsafe { _mm_movemask_epi8(_mm_cmpeq_epi8(self.0, _mm_set1_epi8(byte as i8))) as u32 }
        }
        #[inline]
        pub fn available(&self) -> u32 {
            unsafe { _mm_movemask_epi8(self.0) as u32 }
        }
    }
}

// Keep host policy tests portable; the shipped kernel target is Windows x64.
#[cfg(any(not(target_arch = "x86_64"), test))]
mod scalar {
    const HIGH_BITS: u64 = 0x8080808080808080;
    const LOW_BITS: u64 = 0x7f7f7f7f7f7f7f7f;
    pub const WIDTH: usize = 8;
    pub struct Group(u64);
    impl Group {
        pub unsafe fn load(data: *const u8) -> Self {
            Self(u64::from_le(unsafe {
                core::ptr::read_unaligned(data.cast())
            }))
        }
        fn lanes(mut bytes: u64) -> u32 {
            let mut result = 0;
            while bytes != 0 {
                result |= 1 << (bytes.trailing_zeros() / 8);
                bytes &= bytes - 1;
            }
            result
        }
        pub fn matches(&self, byte: u8) -> u32 {
            let x = self.0 ^ (u64::from(byte) * 0x0101010101010101);
            // Exact byte equality, without borrows into neighboring lanes.
            Self::lanes(!(((x & LOW_BITS).wrapping_add(LOW_BITS)) | x | LOW_BITS) & HIGH_BITS)
        }
        pub fn available(&self) -> u32 {
            Self::lanes(self.0 & HIGH_BITS)
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) use implementation::{Group, WIDTH};
#[cfg(not(target_arch = "x86_64"))]
pub(super) use scalar::{Group, WIDTH};

#[cfg(test)]
mod tests {
    #[test]
    fn scalar_masks_match_each_initialized_byte_and_lane() {
        for byte in 0..=255u8 {
            for lane in 0..super::scalar::WIDTH {
                let mut bytes = [byte ^ 1; super::scalar::WIDTH];
                bytes[lane] = byte;
                let group = unsafe { super::scalar::Group::load(bytes.as_ptr()) };
                assert_eq!(group.matches(byte), 1 << lane);
                let available = bytes
                    .iter()
                    .enumerate()
                    .fold(0, |mask, (i, b)| mask | (u32::from(b & 0x80 != 0) << i));
                assert_eq!(group.available(), available);
            }
        }
    }
}
