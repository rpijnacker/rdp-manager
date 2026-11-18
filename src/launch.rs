//! Starten van de echte RDP-client. De app tekent zelf geen sessie, dus schalen,
//! dynamische resolutie en multimonitor worden door mstsc / xfreerdp afgehandeld.

use crate::model::Connection;

/// Inhoud van een .rdp-bestand. Bevat bewust géén wachtwoord.
pub fn rdp_file(c: &Connection) -> String {
    let mut s = String::new();
    let mut kv = |k: &str, t: &str, v: String| s.push_str(&format!("{k}:{t}:{v}\r\n"));
    kv("full address", "s", if c.port == 3389 { c.host.clone() } else { format!("{}:{}", c.host, c.port) });
    if !c.username.is_empty() {
        let user = if c.domain.is_empty() { c.username.clone() } else { format!("{}\\{}", c.domain, c.username) };
        kv("username", "s", user);
    }
    kv("screen mode id", "i", if c.fullscreen { "2" } else { "1" }.into());
    kv("use multimon", "i", (c.multimon as u8).to_string());
    kv("dynamic resolution", "i", (c.dynamic_resolution as u8).to_string());
    kv("smart sizing", "i", (c.smart_sizing as u8).to_string());
    kv("desktopscalefactor", "i", c.scale.to_string());
    kv("prompt for credentials", "i", "0".into());
    kv("enablecredsspsupport", "i", "1".into());
    kv("authentication level", "i", "2".into());
    s
}

/// Argumenten voor xfreerdp (FreeRDP 3), zonder wachtwoord (dat gaat via stdin).
pub fn xfreerdp_args(c: &Connection) -> Vec<String> {
    let mut a = vec![format!("/v:{}:{}", c.host, c.port), format!("/title:{}", c.name), "/cert:ignore".into()];
    if !c.username.is_empty() {
        a.push(format!("/u:{}", c.username));
    }
    if !c.domain.is_empty() {
        a.push(format!("/d:{}", c.domain));
    }
    if c.fullscreen {
        a.push("/f".into());
    }
    if c.multimon {
        a.push("/multimon".into());
    }
    if c.dynamic_resolution {
        a.push("/dynamic-resolution".into());
    }
    if c.smart_sizing {
        a.push("/smart-sizing".into());
    }
    if c.scale != 100 {
        a.push(format!("/scale-desktop:{}", c.scale));
    }
    a
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("starten mislukt: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[cfg(windows)]
pub fn launch(c: &Connection) -> Result<(), LaunchError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::*;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    let target = format!("TERMSRV/{}", c.host);
    let user = if c.domain.is_empty() { c.username.clone() } else { format!("{}\\{}", c.domain, c.username) };
    let mut have_cred = false;
    if !c.password.is_empty() {
        // Tijdelijke credential in de Credential Manager, zodat mstsc niet om een wachtwoord vraagt.
        // Het wachtwoord komt niet in een bestand of op een commandoregel.
        let mut target_w = wide(&target);
        let mut user_w = wide(&user);
        let blob: Vec<u16> = c.password.encode_utf16().collect();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_w.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: (blob.len() * 2) as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_SESSION,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user_w.as_mut_ptr(),
        };
        have_cred = unsafe { CredWriteW(&cred, 0) } != 0;
        if !have_cred {
            return Err(LaunchError::Other("CredWriteW mislukt".into()));
        }
    }

    let dir = std::env::temp_dir();
    let path = dir.join(format!("rdpm-{}.rdp", &c.id[..c.id.len().min(8)]));
    std::fs::write(&path, rdp_file(c))?;
    let mut child = std::process::Command::new("mstsc.exe").arg(&path).spawn()?;

    // Opruimen: .rdp-bestand en tijdelijke credential verwijderen zodra mstsc verbonden is.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        let _ = std::fs::remove_file(&path);
        if have_cred {
            let t = wide(&target);
            unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) };
        }
        let _ = child.try_wait();
    });
    Ok(())
}

#[cfg(not(windows))]
pub fn launch(c: &Connection) -> Result<(), LaunchError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut args = xfreerdp_args(c);
    if !c.password.is_empty() {
        // Via stdin, zodat het wachtwoord niet in de procslijst staat.
        args.push(format!("/p:{}", c.password));
    }
    let mut child = Command::new("xfreerdp").arg("/args-from:stdin").stdin(Stdio::piped()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(args.join("\n").as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_file_has_scaling_and_no_password() {
        let c = Connection { host: "srv".into(), port: 3390, username: "ad".into(), domain: "CORP".into(), password: "geheim".into(), scale: 150, ..Default::default() };
        let f = rdp_file(&c);
        assert!(f.contains("full address:s:srv:3390"));
        assert!(f.contains("username:s:CORP\\ad"));
        assert!(f.contains("desktopscalefactor:i:150"));
        assert!(f.contains("dynamic resolution:i:1"));
        assert!(f.contains("smart sizing:i:1"));
        assert!(!f.contains("geheim"));
    }

    #[test]
    fn xfreerdp_flags() {
        let c = Connection { host: "srv".into(), scale: 200, fullscreen: true, ..Default::default() };
        let a = xfreerdp_args(&c);
        assert!(a.contains(&"/scale-desktop:200".to_string()));
        assert!(a.contains(&"/dynamic-resolution".to_string()));
        assert!(a.contains(&"/f".to_string()));
        assert!(!a.iter().any(|x| x.starts_with("/p:")));
    }
}
