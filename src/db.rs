//! Opslag in een SQLite-bestand via `turso` (SQLite in pure Rust, geen C-code).
//! Alle connectiegegevens (naam, host, gebruiker, wachtwoord, ...) staan als één
//! versleutelde blob per rij; in de database staat niets leesbaars behalve het
//! willekeurige id.

use crate::crypto::{CryptoError, Vault, derive_key, random_bytes};
#[cfg(any(windows, target_os = "macos"))]
use crate::crypto::KEY_LEN;
use crate::model::Connection;
use std::path::Path;
use turso::Value;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sql(#[from] turso::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verkeerd hoofdwachtwoord")]
    WrongPassword,
    #[error("keyring: {0}")]
    Keyring(String),
    #[error("runtime: {0}")]
    Runtime(String),
}

pub struct Store {
    rt: tokio::runtime::Runtime,
    _db: turso::Database,
    conn: turso::Connection,
    vault: Vault,
}

const VERIFIER: &[u8] = b"rdp-manager-verifier-v1";

struct Raw {
    rt: tokio::runtime::Runtime,
    db: turso::Database,
    conn: turso::Connection,
}

fn open_raw(path: &Path) -> Result<Raw, DbError> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| DbError::Runtime(e.to_string()))?;
    let p = path.to_string_lossy().to_string();
    let (db, conn) = rt.block_on(async {
        let db = turso::Builder::new_local(&p).build().await?;
        let conn = db.connect()?;
        conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB NOT NULL)", ()).await?;
        conn.execute("CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY, data BLOB NOT NULL)", ()).await?;
        Ok::<_, turso::Error>((db, conn))
    })?;
    Ok(Raw { rt, db, conn })
}

impl Raw {
    fn meta_get(&self, k: &str) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self.rt.block_on(async {
            let mut rows = self.conn.query("SELECT value FROM meta WHERE key=?1", [k]).await?;
            match rows.next().await? {
                Some(r) => match r.get_value(0)? {
                    Value::Blob(b) => Ok::<_, turso::Error>(Some(b)),
                    _ => Ok(None),
                },
                None => Ok(None),
            }
        })?)
    }
    fn meta_set(&self, k: &str, v: &[u8]) -> Result<(), DbError> {
        self.rt.block_on(async {
            self.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", vec![Value::Text(k.into()), Value::Blob(v.to_vec())]).await
        })?;
        Ok(())
    }
    fn finish(self, vault: Vault) -> Store {
        Store { rt: self.rt, _db: self.db, conn: self.conn, vault }
    }
}

impl Store {
    /// Sleutel afgeleid van een hoofdwachtwoord (Argon2id). Werkt op alle platforms.
    pub fn open_with_password(path: &Path, password: &str) -> Result<Self, DbError> {
        let raw = open_raw(path)?;
        let salt = match raw.meta_get("salt")? {
            Some(s) => s,
            None => {
                let s = random_bytes::<16>()?.to_vec();
                raw.meta_set("salt", &s)?;
                s
            }
        };
        let vault = Vault::new(derive_key(password, &salt)?);
        match raw.meta_get("verifier")? {
            Some(blob) => {
                vault.open(b"verifier", &blob).map_err(|_| DbError::WrongPassword)?;
            }
            None => raw.meta_set("verifier", &vault.seal(b"verifier", VERIFIER)?)?,
        }
        Ok(raw.finish(vault))
    }

    /// Willekeurige sleutel in de OS-keyring (Windows Credential Manager / macOS Keychain).
    #[cfg(any(windows, target_os = "macos"))]
    pub fn open_with_keyring(path: &Path) -> Result<Self, DbError> {
        let entry = keyring::Entry::new("rdp-manager", "database-key").map_err(|e| DbError::Keyring(e.to_string()))?;
        let key = match entry.get_password() {
            Ok(h) => {
                let v = hex::decode(h.trim()).map_err(|e| DbError::Keyring(e.to_string()))?;
                let arr: [u8; KEY_LEN] = v.try_into().map_err(|_| DbError::Keyring("ongeldige sleutel".into()))?;
                Zeroizing::new(arr)
            }
            Err(keyring::Error::NoEntry) => {
                let k = Zeroizing::new(random_bytes::<KEY_LEN>()?);
                entry.set_password(&hex::encode(*k)).map_err(|e| DbError::Keyring(e.to_string()))?;
                k
            }
            Err(e) => return Err(DbError::Keyring(e.to_string())),
        };
        let raw = open_raw(path)?;
        let vault = Vault::new(key);
        match raw.meta_get("verifier")? {
            Some(blob) => {
                vault.open(b"verifier", &blob).map_err(|_| DbError::Keyring("sleutel past niet bij database".into()))?;
            }
            None => raw.meta_set("verifier", &vault.seal(b"verifier", VERIFIER)?)?,
        }
        Ok(raw.finish(vault))
    }

    pub fn save(&self, c: &mut Connection) -> Result<(), DbError> {
        if c.id.is_empty() {
            c.id = hex::encode(random_bytes::<16>()?);
        }
        let json = Zeroizing::new(serde_json::to_vec(c)?);
        let blob = self.vault.seal(c.id.as_bytes(), &json)?;
        self.rt.block_on(async {
            self.conn.execute("INSERT OR REPLACE INTO connections(id,data) VALUES(?1,?2)", vec![Value::Text(c.id.clone()), Value::Blob(blob)]).await
        })?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<(), DbError> {
        self.rt.block_on(async { self.conn.execute("DELETE FROM connections WHERE id=?1", [id]).await })?;
        Ok(())
    }

    fn raw_rows(&self) -> Result<Vec<(String, Vec<u8>)>, DbError> {
        Ok(self.rt.block_on(async {
            let mut rows = self.conn.query("SELECT id,data FROM connections", ()).await?;
            let mut out = Vec::new();
            while let Some(r) = rows.next().await? {
                if let (Value::Text(id), Value::Blob(b)) = (r.get_value(0)?, r.get_value(1)?) {
                    out.push((id, b));
                }
            }
            Ok::<_, turso::Error>(out)
        })?)
    }

    pub fn list(&self) -> Result<Vec<Connection>, DbError> {
        let mut out = Vec::new();
        for (id, blob) in self.raw_rows()? {
            let plain = self.vault.open(id.as_bytes(), &blob)?;
            let mut c: Connection = serde_json::from_slice(&plain)?;
            c.id = id;
            out.push(c);
        }
        out.sort_by(|a, b| (a.folder.to_lowercase(), a.name.to_lowercase()).cmp(&(b.folder.to_lowercase(), b.name.to_lowercase())));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rdpm-{}-{}.db", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn roundtrip_and_nothing_plaintext_on_disk() {
        let p = tmp("rt");
        {
            let s = Store::open_with_password(&p, "hoofd").unwrap();
            let mut c = Connection { name: "Prod".into(), host: "srv-geheim.example".into(), password: "S3cr3t!".into(), ..Default::default() };
            s.save(&mut c).unwrap();
            let l = s.list().unwrap();
            assert_eq!(l.len(), 1);
            assert_eq!(l[0].password, "S3cr3t!");
            assert_eq!(l[0].id, c.id);
        }
        // Alle bestanden van deze database (hoofdbestand, WAL, log) controleren.
        let prefix = p.file_name().unwrap().to_string_lossy().to_string();
        let mut checked = 0;
        for e in std::fs::read_dir(p.parent().unwrap()).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let raw = std::fs::read(e.path()).unwrap();
                checked += raw.len();
                for needle in [&b"S3cr3t!"[..], b"srv-geheim", b"Prod"] {
                    assert!(!raw.windows(needle.len()).any(|w| w == needle), "plaintext gevonden in {:?}", e.path());
                }
            }
        }
        assert!(checked > 0, "geen databasebestanden gevonden");
    }

    #[test]
    fn wrong_password_rejected() {
        let p = tmp("wp");
        Store::open_with_password(&p, "goed").unwrap();
        assert!(matches!(Store::open_with_password(&p, "fout"), Err(DbError::WrongPassword)));
        assert!(Store::open_with_password(&p, "goed").is_ok());
    }

    #[test]
    fn swapped_blob_between_rows_detected() {
        let p = tmp("sw");
        let s = Store::open_with_password(&p, "x").unwrap();
        let (mut a, mut b) = (Connection { name: "a".into(), ..Default::default() }, Connection { name: "b".into(), ..Default::default() });
        s.save(&mut a).unwrap();
        s.save(&mut b).unwrap();
        let blob_a = s.raw_rows().unwrap().into_iter().find(|(id, _)| *id == a.id).unwrap().1;
        s.rt.block_on(s.conn.execute("UPDATE connections SET data=?1 WHERE id=?2", vec![Value::Blob(blob_a), Value::Text(b.id.clone())])).unwrap();
        assert!(s.list().is_err());
    }
}
