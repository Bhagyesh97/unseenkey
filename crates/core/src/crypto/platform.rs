//! Best-effort memory locking for secret buffers (`mlock` / `VirtualLock`), so
//! plaintext is not swapped to disk or written into core dumps.
//!
//! This is defence in depth, not a boundary: every platform caps how much a
//! process may lock, locking is page-granular (unlocking one buffer may
//! unlock a neighbour on the same page), and the scrubber's automaton holds
//! copies of every value unlocked. Failures are therefore ignored.
//!
//! The only `unsafe` in this crate lives here.

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
#[allow(unsafe_code)]
pub(crate) fn lock(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // SAFETY: `buf` is a live, exclusively borrowed region; `mlock` only
    // changes the paging attributes of the pages that contain it.
    unsafe { memsec::mlock(buf.as_mut_ptr(), buf.len()) }
}

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
#[allow(unsafe_code)]
pub(crate) fn unlock(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // SAFETY: same region as passed to `lock`; `munlock` zeroes it and
    // restores normal paging. The caller zeroizes again afterwards.
    unsafe { memsec::munlock(buf.as_mut_ptr(), buf.len()) }
}

#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
pub(crate) fn lock(_buf: &mut [u8]) -> bool {
    false
}

#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
pub(crate) fn unlock(_buf: &mut [u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_never_panic() {
        let mut small = alloc::vec![7u8; 32];
        let _ = lock(&mut small);
        let _ = unlock(&mut small);
        let mut empty: alloc::vec::Vec<u8> = alloc::vec![];
        assert!(!lock(&mut empty));
        assert!(!unlock(&mut empty));
    }
}
