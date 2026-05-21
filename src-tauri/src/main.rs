#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let config = yara_kiosk_lib::KioskConfig::from_args();
    yara_kiosk_lib::run(config);
}
