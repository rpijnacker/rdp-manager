# rdp-manager

Een kleine, snel startende RDP-connectiemanager in Rust (egui). Geen Electron.

- Connecties staan versleuteld (XChaCha20-Poly1305) in een lokale SQLite-database, via de pure-Rust `turso`-crate.
- Windows/macOS: sleutel in de OS-keyring. Linux: hoofdwachtwoord (Argon2id).
- Start de echte RDP-client (`mstsc` / `xfreerdp`) met schaal, dynamische resolutie en multimonitor.
- Import vanuit Devolutions Remote Desktop Manager (JSON/XML).

```bash
cargo build --release
```

Status: eerste versie. De Windows-onderdelen (keyring, `mstsc`, schalen) zijn nog niet uitgebreid getest. `turso` is een jonge crate.

## Licentie

Naar keuze onder [MIT](LICENSE-MIT) of [Apache-2.0](LICENSE-APACHE).
