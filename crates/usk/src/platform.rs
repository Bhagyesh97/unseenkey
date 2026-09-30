//! Platform-specific helpers. The only place in this crate where `unsafe` is
//! permitted; keep it small and reviewed.

/// Stop our own stdin/stdout/stderr handles from being inherited by children.
///
/// On Windows, `CreateProcess` copies every inheritable handle into the child
/// even when the child's standard handles are redirected. A daemon spawned from
/// `usk ls | head` would otherwise hold the pipe's write end open and `head`
/// would wait forever. Rust duplicates standard handles explicitly for children
/// that inherit stdio, so clearing the flag here has no other effect.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn disable_std_handle_inheritance() {
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: `GetStdHandle` takes one of three documented constants and
        // returns either a handle owned by this process for its lifetime, null,
        // or INVALID_HANDLE_VALUE; we skip the latter two. `SetHandleInformation`
        // only changes the inherit flag on that handle and cannot invalidate it.
        unsafe {
            let h = GetStdHandle(id);
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                continue;
            }
            SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

/// No-op elsewhere: Unix file descriptors are close-on-exec by default in Rust.
#[cfg(not(windows))]
pub fn disable_std_handle_inheritance() {}
