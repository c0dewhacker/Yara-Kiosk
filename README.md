# Yara Kiosk

A Tauri 2 desktop application for kiosk-mode malware scanning using [YARA-X](https://virustotal.github.io/yara-x/). Designed to run on dedicated scanning stations — insert a USB drive, hit scan, get a report, all without a browser or internet access required at scan time.

## Features

- **USB auto-detection** — detects inserted drives and offers one-click scanning
- **YARA-X scanning** — parallel file scanning with real-time progress
- **In-app reports** — scan results viewed directly inside the app (no browser needed)
- **Rule management** — virtual-scrolled rule browser with enable/disable per-file control
- **Rule sources** — fetch from [YARA Forge](https://yarahq.github.io/), Google Threat Intelligence (GTI), arbitrary URLs, or local directories
- **Rule packages** — import/export `.ykpk` bundles; drop a package in the data directory for zero-interaction updates
- **Auth gate** — password-protected settings and rule management views using system PAM (Linux) or Windows Logon
- **Kiosk mode** — `--fullscreen` / `--kiosk` flag, custom data directory via `--data-dir`

## Requirements

### All platforms
- **Rust** 1.80 or later — [rustup.rs](https://rustup.rs)
- **Node.js** 18 or later with npm

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  librsvg2-dev \
  libssl-dev \
  patchelf \
  libayatana-appindicator3-dev \
  libpam0g-dev
```

### Windows

- **WebView2 runtime** — pre-installed on Windows 11; download from Microsoft for Windows 10
- No additional system libraries required

## Building

```bash
git clone https://github.com/c0dewhacker/Yara-Kiosk.git
cd Yara-Kiosk
npm install
```

### Ubuntu — produces `.AppImage`

```bash
npm run tauri build
# Output: src-tauri/target/release/bundle/appimage/yara-kiosk_*.AppImage
```

### Windows — produces NSIS installer (`.exe`)

```powershell
npm run tauri build
# Output: src-tauri\target\release\bundle\nsis\Yara-Kiosk_*_x64-setup.exe
```

> **Code signing** — Tauri can sign builds using `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. See the [Tauri signing docs](https://tauri.app/distribute/sign/) for setup. Unsigned builds will show a Windows SmartScreen warning on first run.

## Development

```bash
npm run tauri dev   # hot-reload dev build
```

Tauri watches both the Vite frontend and the Rust backend. Frontend changes hot-reload instantly; Rust changes trigger a recompile.

## Running

### Standard

```bash
./yara-kiosk                         # Linux AppImage or Windows exe
```

### Kiosk mode (fullscreen, locked window controls)

```bash
./yara-kiosk --fullscreen
# or
./yara-kiosk --kiosk
```

### Custom data directory

Rules, reports, and settings are stored in the platform app-data directory by default. Override with:

```bash
./yara-kiosk --data-dir=/mnt/usb-config
```

All three flags can be combined:

```bash
./yara-kiosk --kiosk --data-dir=/opt/yara-kiosk-data
```

## Data directory layout

```
<data-dir>/
  rules/
    yara_forge_core/     # YARA Forge — Core tier
    yara_forge_extended/ # YARA Forge — Extended tier
    yara_forge_full/     # YARA Forge — Full tier
    gti/                 # Google Threat Intelligence rules
    url_<id>/            # URL-fetched rulesets
  reports/               # HTML scan reports
  sources.json           # Configured rule sources
  disabled_rules.json    # Per-file enable/disable state
  settings.json          # App settings
```

Dropping a `.ykpk` rule package into the data directory root is auto-imported on next launch and then deleted — useful for air-gapped kiosk rule updates via USB.

## Rule sources

| Source | Description |
|--------|-------------|
| YARA Forge | Community ruleset — Core / Extended / Full tiers |
| GTI | Google Threat Intelligence (requires API key in Settings) |
| URL | Fetch a `.yar` / `.yara` / `.zip` file from any HTTPS URL |
| Directory | Point at a local folder of existing rule files |

## Authentication

Settings and rule management are protected by a system password prompt. On Linux this uses PAM; on Windows it uses `LogonUserW`. The password is never stored by the app — it is verified against the OS user account.

## License

MIT
