pub mod extract;
pub mod list;
pub mod metadata;
pub mod ota_metadata;
pub mod verify;

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Parser, Subcommand};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold().underline())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Green.on_default())
    .invalid(AnsiColor::Yellow.on_default());

#[derive(Parser)]
#[command(
    name = "payload-extract",
    version,
    about = "Android OTA payload.bin extractor",
    styles = STYLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Skip SSL certificate verification for HTTPS URLs
    #[arg(short = 'k', long, global = true)]
    pub insecure: bool,

    /// User-Agent header for HTTP requests (default: an Android OTA client UA)
    #[arg(short = 'A', long, value_name = "UA", global = true)]
    pub user_agent: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Extract partition images from payload.bin
    Extract(extract::ExtractArgs),
    /// List partitions in payload.bin
    List(list::ListArgs),
    /// Verify extracted partition images against payload hashes
    Verify(verify::VerifyArgs),
    /// Show payload metadata
    Metadata(metadata::MetadataArgs),
    /// Show OTA package metadata (META-INF/com/android/metadata{,.pb})
    OtaMetadata(ota_metadata::OtaMetadataArgs),
}
