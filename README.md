# Yara Kiosk

A Tauri 2 desktop application for kiosk-mode malware scanning using [YARA-X](https://virustotal.github.io/yara-x/). Insert a USB drive, hit scan, get a report — no browser or internet access required at scan time.

## Features

- **USB auto-detection** — detects inserted drives and offers one-click scanning (Linux and Windows)
- **YARA-X scanning** — parallel file scanning with real-time progress and a live match feed
- **Scan reports** — results viewed in-app; export or delete reports from the report viewer
- **Rule management** — browse, enable/disable, and fetch rules from YARA Forge, Google Threat Intelligence, URLs, or local directories
- **Auth gate** — settings and rule management protected by system PAM (Linux) or Windows Logon
- **Kiosk mode** — `--fullscreen` / `--kiosk` flags; custom data directory via `--data-dir`

## Requirements

- **Rust** 1.80+ — [rustup.rs](https://rustup.rs)
- **Node.js** 18+ with npm

### Ubuntu / Debian

```bash
sudo apt-get install -y \
  libgtk-3-dev libwebkit2gtk-4.1-dev librsvg2-dev \
  libssl-dev patchelf libayatana-appindicator3-dev libpam0g-dev
```

### Windows

WebView2 runtime is required — pre-installed on Windows 11, otherwise download from Microsoft.

## Building

```bash
git clone https://github.com/c0dewhacker/Yara-Kiosk.git
cd Yara-Kiosk
npm install
npm run tauri build
```

Outputs:
- **Linux** — `src-tauri/target/release/bundle/appimage/yara-kiosk_*.AppImage`
- **Windows** — `src-tauri\target\release\bundle\nsis\Yara-Kiosk_*_x64-setup.exe`

## Development

```bash
npm run tauri dev
```

Frontend changes hot-reload instantly; Rust changes trigger a recompile.

## License

MIT
