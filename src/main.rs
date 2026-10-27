use clap::Parser;

mod commands;
use payload_extract::{extract, input, ota_metadata, proto, storage, style};

use commands::{Cli, Commands};

fn main() {
    init_terminal();
    let cli = Cli::parse();
    let insecure = cli.insecure;
    let user_agent = cli.user_agent;
    let ua = user_agent.as_deref();

    let result = match cli.command {
        Commands::Extract(args) => commands::extract::run(args, insecure, ua),
        Commands::List(args) => commands::list::run(args, insecure, ua),
        Commands::Verify(args) => commands::verify::run(args, insecure, ua),
        Commands::Metadata(args) => commands::metadata::run(args, insecure, ua),
        Commands::OtaMetadata(args) => commands::ota_metadata::run(args, insecure, ua),
    };

    if let Err(e) = result {
        eprintln!("{} {e:#}", style::error().apply_to("Error:"));
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn init_terminal() {
    type Handle = *mut std::ffi::c_void;
    type Bool = i32;
    type Dword = u32;

    const STD_INPUT_HANDLE: Dword = -10i32 as u32;
    const ENABLE_QUICK_EDIT_MODE: Dword = 0x0040;
    const ENABLE_EXTENDED_FLAGS: Dword = 0x0080;

    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: Dword) -> Handle;
        fn GetConsoleMode(hConsoleHandle: Handle, lpMode: *mut Dword) -> Bool;
        fn SetConsoleMode(hConsoleHandle: Handle, dwMode: Dword) -> Bool;
    }

    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if !handle.is_null() && handle != -1isize as Handle {
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                mode &= !ENABLE_QUICK_EDIT_MODE;
                mode |= ENABLE_EXTENDED_FLAGS;
                SetConsoleMode(handle, mode);
            }
        }
    }
}

#[cfg(not(windows))]
fn init_terminal() {}
