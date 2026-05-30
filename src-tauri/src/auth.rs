/// Verify the current OS user's password against the system credential store.
/// On Linux/macOS this uses PAM (no root required — the setuid PAM helper
/// `/sbin/unix_chkpwd` does the shadow-file check).
/// On Windows this uses `LogonUserW` with LOGON32_LOGON_INTERACTIVE.
///
/// The username is resolved from the effective UID / token rather than from
/// environment variables, so a user cannot bypass the gate by launching with
/// `USER=other-account ./yara-kiosk`.
pub fn verify_system_password(password: &str) -> Result<bool, String> {
    platform::verify(password)
}

// ── Linux / macOS (PAM) ───────────────────────────────────────────────────────

#[cfg(unix)]
mod platform {
    use std::ffi::CStr;

    fn current_username() -> Result<String, String> {
        unsafe {
            let uid = libc::geteuid();
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                return Err(format!("Cannot resolve username for uid {}", uid));
            }
            let name_ptr = (*pwd).pw_name;
            if name_ptr.is_null() {
                return Err("getpwuid returned null pw_name".to_string());
            }
            CStr::from_ptr(name_ptr)
                .to_str()
                .map(|s| s.to_string())
                .map_err(|e| format!("Invalid UTF-8 in username: {}", e))
        }
    }

    pub fn verify(password: &str) -> Result<bool, String> {
        let username = current_username()?;
        let mut auth = pam::Client::with_password("login")
            .map_err(|_| "PAM initialisation failed".to_string())?;
        auth.conversation_mut().set_credentials(&username, password);
        Ok(auth.authenticate().is_ok())
    }
}

// ── Windows (LogonUserW) ──────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    };
    use windows::Win32::System::WindowsProgramming::GetUserNameW;
    use windows::core::PCWSTR;

    fn current_username() -> Result<String, String> {
        // UNLEN (256) + 1 for null terminator.
        let mut buf = vec![0u16; 257];
        let mut len = buf.len() as u32;
        unsafe {
            // windows 0.62 changed lpbuffer to Option<PWSTR>; wrap explicitly.
            GetUserNameW(
                Some(windows::core::PWSTR(buf.as_mut_ptr())),
                &mut len,
            )
            .map_err(|e| format!("GetUserNameW failed: {}", e))?;
        }
        // `len` includes the null terminator on success.
        let end = (len as usize).saturating_sub(1).min(buf.len());
        Ok(String::from_utf16_lossy(&buf[..end]))
    }

    pub fn verify(password: &str) -> Result<bool, String> {
        let username = current_username()?;
        // "." is the local machine domain for non-domain-joined accounts.
        // For domain-joined accounts the token resolves correctly with ".".
        let domain = ".".to_string();

        let u: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
        let d: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
        let p: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();

        let mut token = HANDLE::default();
        let ok = unsafe {
            LogonUserW(
                PCWSTR(u.as_ptr()),
                PCWSTR(d.as_ptr()),
                PCWSTR(p.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
            .is_ok()
        };

        if ok {
            unsafe { let _ = CloseHandle(token); }
        }

        Ok(ok)
    }
}

// ── Other platforms ───────────────────────────────────────────────────────────

#[cfg(not(any(unix, target_os = "windows")))]
mod platform {
    pub fn verify(_password: &str) -> Result<bool, String> {
        Err("Password verification is not supported on this platform".to_string())
    }
}
