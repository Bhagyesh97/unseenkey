//! OS hooks that lock the vault: session lock and suspend. The only place in
//! this crate where `unsafe` is permitted; keep it small and reviewed.
//!
//! Two mechanisms, both best effort:
//! - [`watch_system`] subscribes to the OS (Windows: `WM_WTSSESSION_CHANGE`
//!   through a message-only window and `PBT_APMSUSPEND` through a power
//!   notification callback). Other platforms are a no-op for now.
//! - [`watch_resume`] is portable: a thread sleeps in short steps and treats a
//!   wall-clock jump as "the machine was asleep", so a sleep that the OS hook
//!   missed still ends with a locked vault when the machine wakes.

use std::time::{Duration, SystemTime};

/// Reason strings passed to the callbacks (and written to the audit log).
pub const REASON_SLEEP: &str = "sleep";
/// The interactive session was locked (Win+L, lock screen).
pub const REASON_SESSION_LOCK: &str = "session_lock";

/// How often the resume detector samples the clock.
const RESUME_INTERVAL: Duration = Duration::from_secs(5);
/// A gap this much beyond the interval counts as a suspend.
const RESUME_SLACK: Duration = Duration::from_secs(90);

/// True when the wall clock advanced far more than `interval` between two
/// samples. A clock set backwards is ignored.
pub fn resumed(last: SystemTime, now: SystemTime, interval: Duration) -> bool {
    match now.duration_since(last) {
        Ok(gap) => gap > interval + RESUME_SLACK,
        Err(_) => false,
    }
}

/// Spawn the resume detector; `on_resume` runs on its thread after a wake.
pub fn watch_resume(on_resume: impl Fn() + Send + 'static) {
    std::thread::Builder::new()
        .name("usk-resume-watch".into())
        .spawn(move || {
            let mut last = SystemTime::now();
            loop {
                std::thread::sleep(RESUME_INTERVAL);
                let now = SystemTime::now();
                if resumed(last, now, RESUME_INTERVAL) {
                    on_resume();
                }
                last = now;
            }
        })
        .expect("spawn resume watcher");
}

/// Subscribe to OS session-lock and suspend notifications. `on_event` receives
/// [`REASON_SLEEP`] or [`REASON_SESSION_LOCK`] on a watcher thread. Returns an
/// error only when the subscription could not be set up; callers log and go on.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn watch_system(
    on_event: impl Fn(&'static str) + Send + Sync + 'static,
) -> std::io::Result<()> {
    use std::sync::OnceLock;
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::{
        RegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, DEVICE_NOTIFY_CALLBACK, HWND_MESSAGE, MSG, PBT_APMSUSPEND,
        WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_SESSION_LOCK,
    };

    type Hook = Box<dyn Fn(&'static str) + Send + Sync>;
    static HOOK: OnceLock<Hook> = OnceLock::new();
    if HOOK.set(Box::new(on_event)).is_err() {
        return Err(std::io::Error::other("system watcher already installed"));
    }
    fn fire(reason: &'static str) {
        if let Some(h) = HOOK.get() {
            h(reason);
        }
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_WTSSESSION_CHANGE && wparam as u32 == WTS_SESSION_LOCK {
            fire(REASON_SESSION_LOCK);
            return 0;
        }
        // SAFETY: forwarding the message we were given to the default handler.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    unsafe extern "system" fn power_cb(
        _context: *const core::ffi::c_void,
        kind: u32,
        _setting: *const core::ffi::c_void,
    ) -> u32 {
        if kind == PBT_APMSUSPEND {
            fire(REASON_SLEEP);
        }
        0
    }

    let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<()>>();
    std::thread::Builder::new()
        .name("usk-session-watch".into())
        .spawn(move || {
            let class: Vec<u16> = "UnseenkeySessionWatch\0".encode_utf16().collect();
            // SAFETY: plain Win32 calls with valid, owned arguments; the window
            // class name outlives the window because this thread never returns
            // while the message loop runs.
            let result = unsafe {
                let hinstance = GetModuleHandleW(core::ptr::null());
                let mut wc: WNDCLASSW = core::mem::zeroed();
                wc.lpfnWndProc = Some(wndproc);
                wc.hInstance = hinstance;
                wc.lpszClassName = class.as_ptr();
                if RegisterClassW(&wc) == 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    let hwnd = CreateWindowExW(
                        0,
                        class.as_ptr(),
                        class.as_ptr(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        HWND_MESSAGE,
                        core::ptr::null_mut(),
                        hinstance,
                        core::ptr::null(),
                    );
                    if hwnd.is_null() {
                        Err(std::io::Error::last_os_error())
                    } else {
                        let ok: BOOL =
                            WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
                        if ok == 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            // The parameter block must outlive the registration: leak it.
                            let params = Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                                Callback: Some(power_cb),
                                Context: core::ptr::null_mut(),
                            }));
                            let _ = RegisterSuspendResumeNotification(
                                params as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS as HANDLE,
                                DEVICE_NOTIFY_CALLBACK,
                            );
                            Ok(())
                        }
                    }
                }
            };
            let failed = result.is_err();
            let _ = tx.send(result);
            if failed {
                return;
            }
            // SAFETY: standard message loop on this thread's own window.
            unsafe {
                let mut msg: MSG = core::mem::zeroed();
                while GetMessageW(&mut msg, core::ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        })?;
    rx.recv()
        .unwrap_or_else(|_| Err(std::io::Error::other("session watcher thread died")))
}

/// No OS hooks on this platform yet; the resume detector still applies.
#[cfg(not(windows))]
pub fn watch_system(
    _on_event: impl Fn(&'static str) + Send + Sync + 'static,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_detection_needs_a_real_gap() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let iv = Duration::from_secs(5);
        assert!(!resumed(t0, t0 + iv, iv));
        assert!(!resumed(t0, t0 + iv + Duration::from_secs(60), iv));
        assert!(resumed(t0, t0 + iv + Duration::from_secs(91), iv));
        assert!(resumed(t0, t0 + Duration::from_secs(3600), iv));
        // Clock stepped backwards: not a resume.
        assert!(!resumed(t0 + Duration::from_secs(500), t0, iv));
    }
}
