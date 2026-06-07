// AetherOS desktop shell entry point.
//
// The governance moat lives in the Python control-plane API (which itself calls the
// Rust `aether-core` crate via PyO3). This Tauri shell hosts the React UI and spawns
// the control-plane as a managed sidecar so the whole product ships as one native app.
// Keeping the shell thin means the desktop layer carries no security-critical logic.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running AetherOS desktop shell");
}
