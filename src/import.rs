//! Import van Devolutions Remote Desktop Manager-exports (JSON en XML/.rdm).
//!
//! De importer is bewust tolerant: veldnamen worden hoofdletter-ongevoelig
//! opgezocht, ook in geneste objecten. Alleen RDP-connecties worden overgenomen
//! (mappen en andere typen, zoals SSH, worden overgeslagen).
//! Wachtwoorden worden alleen overgenomen als daar om gevraagd wordt, en dan
//! precies zoals ze in het bestand staan. Is de export door RDM versleuteld,
//! dan komt er onbruikbare tekst binnen: exporteer in dat geval met
//! "gevoelige gegevens meenemen" naar leesbaar JSON.

use crate::model::Connection;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("bestand is geen geldige JSON of XML: {0}")]
    Parse(String),
    #[error("geen RDP-connecties gevonden")]
    Empty,
}

type Flat = HashMap<String, String>;

const HOST_KEYS: &[&str] = &["url", "host", "hostname", "computername", "server", "address", "fulladdress"];
const USER_KEYS: &[&str] = &["username", "user", "login"];
const GROUP_KEYS: &[&str] = &["group", "folder", "path"];
const PORT_KEYS: &[&str] = &["port", "rdpport"];

pub fn parse_rdm(text: &str, include_passwords: bool) -> Result<Vec<Connection>, ImportError> {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    let flats = if t.starts_with('{') || t.starts_with('[') {
        let v: Value = serde_json::from_str(t).map_err(|e| ImportError::Parse(e.to_string()))?;
        let mut out = Vec::new();
        visit_json(&v, &mut out);
        out
    } else {
        let doc = roxmltree::Document::parse(t).map_err(|e| ImportError::Parse(e.to_string()))?;
        let mut out = Vec::new();
        for n in doc.descendants().filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("connection")) {
            let mut flat = Flat::new();
            flatten_xml(n, &mut flat);
            out.push(flat);
        }
        out
    };
    let conns: Vec<Connection> = flats.iter().filter_map(|f| to_connection(f, include_passwords)).collect();
    if conns.is_empty() { Err(ImportError::Empty) } else { Ok(conns) }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Eigen (niet-geneste) velden eerst, zodat ondiepe sleutels winnen.
fn flatten_json(v: &Value, flat: &mut Flat) {
    let Some(obj) = v.as_object() else { return };
    for (k, v) in obj {
        if let Some(s) = scalar(v) {
            flat.entry(k.to_lowercase()).or_insert(s);
        }
    }
    for v in obj.values() {
        if v.is_object() {
            flatten_json(v, flat);
        }
    }
}

fn visit_json(v: &Value, out: &mut Vec<Flat>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| visit_json(x, out)),
        Value::Object(o) => {
            if o.keys().any(|k| k.eq_ignore_ascii_case("name")) {
                let mut flat = Flat::new();
                flatten_json(v, &mut flat);
                if HOST_KEYS.iter().any(|k| flat.contains_key(*k)) {
                    out.push(flat);
                }
            }
            o.values().for_each(|x| visit_json(x, out));
        }
        _ => {}
    }
}

fn flatten_xml(n: roxmltree::Node, flat: &mut Flat) {
    for a in n.attributes() {
        flat.entry(a.name().to_lowercase()).or_insert(a.value().to_string());
    }
    let kids: Vec<_> = n.children().filter(|c| c.is_element() && !c.tag_name().name().eq_ignore_ascii_case("connection")).collect();
    for c in &kids {
        if !c.children().any(|g| g.is_element()) {
            if let Some(t) = c.text() {
                flat.entry(c.tag_name().name().to_lowercase()).or_insert(t.trim().to_string());
            }
        }
    }
    for c in kids.iter().filter(|c| c.children().any(|g| g.is_element())) {
        flatten_xml(*c, flat);
    }
}

fn first<'a>(flat: &'a Flat, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| flat.get(*k)).map(|s| s.as_str()).filter(|s| !s.trim().is_empty())
}

fn to_connection(flat: &Flat, include_passwords: bool) -> Option<Connection> {
    if let Some(t) = flat.get("connectiontype") {
        let t = t.to_lowercase();
        if !(t.contains("rdp") || t.contains("remotedesktop") || t.contains("terminalserv")) {
            return None;
        }
    }
    let raw_host = first(flat, HOST_KEYS)?.trim();
    // "host", "host:port" of "rdp://host:port"
    let raw_host = raw_host.trim_start_matches("rdp://").trim_end_matches('/');
    let (host, url_port) = match raw_host.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().ok()),
        _ => (raw_host.to_string(), None),
    };
    let port = url_port.or_else(|| first(flat, PORT_KEYS).and_then(|p| p.parse().ok())).unwrap_or(3389);

    let mut username = first(flat, USER_KEYS).unwrap_or("").to_string();
    let mut domain = first(flat, &["domain"]).unwrap_or("").to_string();
    if domain.is_empty() {
        if let Some((d, u)) = username.clone().split_once('\\') {
            domain = d.to_string();
            username = u.to_string();
        }
    }
    let folder = first(flat, GROUP_KEYS).unwrap_or("").replace('\\', "/").trim_matches('/').to_string();
    let name = flat.get("name").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| host.clone());
    let notes = first(flat, &["description", "notes"]).unwrap_or("").to_string();

    let password = if include_passwords { first(flat, &["password", "pwd"]).unwrap_or("").to_string() } else { String::new() };

    Some(Connection { name, folder, host, port, username, domain, password, notes, ..Default::default() })
}

/// Voegt alleen connecties toe die er nog niet zijn (zelfde map, naam en host).
pub fn is_duplicate(existing: &[Connection], c: &Connection) -> bool {
    existing.iter().any(|e| e.name == c.name && e.host == c.host && e.folder == c.folder && e.port == c.port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_export() {
        let j = r#"[
          {"Name":"Productie","ConnectionType":"Group","Group":""},
          {"Name":"DC01","ConnectionType":"RDPConfigured","Group":"Klanten\\ACME","Url":"dc01.acme.local:3390",
           "UserName":"ACME\\beheer","Password":"ENCRYPTED==","Description":"domeincontroller"},
          {"Name":"Linux","ConnectionType":"SSHShell","Group":"Klanten","Url":"10.0.0.5"},
          {"Name":"Web","ConnectionType":"RDPConfigured","Group":"Klanten","Url":"web01","RDP":{"Port":3395},"Domain":"CORP","UserName":"ad"}
        ]"#;
        let c = parse_rdm(j, false).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].name.as_str(), c[0].host.as_str(), c[0].port), ("DC01", "dc01.acme.local", 3390));
        assert_eq!((c[0].domain.as_str(), c[0].username.as_str(), c[0].folder.as_str()), ("ACME", "beheer", "Klanten/ACME"));
        assert!(c[0].password.is_empty(), "wachtwoorden worden niet overgenomen");
        assert_eq!(c[1].port, 3395);
        assert_eq!(c[1].domain, "CORP");
        let with = parse_rdm(j, true).unwrap();
        assert_eq!(with[0].password, "ENCRYPTED==");
        assert!(with[1].password.is_empty());
    }

    #[test]
    fn json_wrapped_in_object() {
        let j = r#"{"Connections":[{"Name":"A","ConnectionType":"RDPConfigured","Url":"a.example"}]}"#;
        assert_eq!(parse_rdm(j, false).unwrap()[0].host, "a.example");
    }

    #[test]
    fn xml_export() {
        let x = r#"<?xml version="1.0"?>
        <ArrayOfConnection>
          <Connection><ConnectionType>RDPConfigured</ConnectionType><Name>SRV1</Name><Group>Intern\Servers</Group>
            <Url>srv1.local</Url><UserName>admin</UserName><Domain>LOCAL</Domain></Connection>
          <Connection><ConnectionType>Group</ConnectionType><Name>Intern</Name></Connection>
        </ArrayOfConnection>"#;
        let c = parse_rdm(x, false).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].name.as_str(), c[0].folder.as_str(), c[0].domain.as_str()), ("SRV1", "Intern/Servers", "LOCAL"));
    }

    #[test]
    fn garbage_and_empty() {
        assert!(matches!(parse_rdm("niets", false), Err(ImportError::Parse(_))));
        assert!(matches!(parse_rdm("[]", false), Err(ImportError::Empty)));
    }

    #[test]
    fn duplicates() {
        let c = parse_rdm(r#"[{"Name":"A","Url":"h"}]"#, false).unwrap();
        assert!(is_duplicate(&c, &c[0]));
    }
}
