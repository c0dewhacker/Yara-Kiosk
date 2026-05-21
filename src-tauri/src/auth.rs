/// Verify the current OS user's password against the system credential store.
/// On Linux/macOS this uses PAM (no root required — the setuid PAM helper
/// `/sbin/unix_chkpwd` does the shadow-file check).
/// On Windows this uses `LogonUserW` with LOGON32_LOGON_INTERACTIVE.
pub fn verify_system_password(password: &str) -> Result<bool, String> {
    platform::verify(password)
}

// ── Linux / macOS (PAM) ───────────────────────────────────────────────────────

#[cfg(unix)]
mod platform {
    pub fn verify(password: &str) -> Result<bool, String> {
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| "Cannot determine current username (USER/LOGNAME not set)".to_string())?;

        let mut auth = pam::Authenticator::with_password("login")
            .map_err(|_| "PAM initialisation failed".to_string())?;
        auth.get_handler().set_credentials(&username, password);
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
    use windows::core::PCWSTR;

    pub fn verify(password: &str) -> Result<bool, String> {
        let username = std::env::var("USERNAME")
            .map_err(|_| "Cannot determine current username (USERNAME not set)".to_string())?;
        // Use "." for the local machine domain, or fall back to USERDOMAIN.
        let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".to_string());

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
