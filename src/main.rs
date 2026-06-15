use clap::Parser;

mod commands;
mod error;
mod extract;
mod input;
mod ota_metadata;
mod payload;
mod proto;
mod style;

use commands::{Cli, Commands};

fn main() {
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
        eprintln!("{} {e}", style::error().apply_to("Error:"));
        std::process::exit(1);
    }
}
