use anyhow::Result;
use clap::Args;

use crate::input;
use crate::ota_metadata::{DeviceState, OtaMetadataPb, TextMetadata};
use crate::style;

#[derive(Args)]
pub struct OtaMetadataArgs {
    /// Path to OTA ZIP or HTTP URL
    pub input: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: OtaMetadataArgs, insecure: bool, user_agent: Option<&str>) -> Result<()> {
    let data = input::read_ota_metadata(&args.input, insecure, user_agent)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    if data.is_empty() {
        println!(
            "{} no META-INF/com/android/metadata{{,.pb}} entries found in archive",
            style::warning().apply_to("Note:")
        );
        return Ok(());
    }

    if let Some(text) = &data.text {
        print_text(text);
    }
    if let Some(pb) = &data.pb {
        if data.text.is_some() {
            println!();
        }
        print_pb(pb);
    }
    Ok(())
}

fn print_text(text: &TextMetadata) {
    println!(
        "{}",
        style::label().apply_to("OTA Metadata (META-INF/com/android/metadata):")
    );
    let key_width = text.entries.keys().map(|k| k.len()).max().unwrap_or(0);
    for (k, v) in &text.entries {
        println!(
            "  {:<width$}  {v}",
            style::bold().apply_to(k),
            width = key_width
        );
    }
}

fn print_pb(pb: &OtaMetadataPb) {
    println!(
        "{}",
        style::label().apply_to("OTA Metadata (META-INF/com/android/metadata.pb):")
    );
    println!("  {} {}", style::label().apply_to("Type:"), pb.r#type);
    println!("  {} {}", style::label().apply_to("Wipe:"), pb.wipe);
    println!(
        "  {} {}",
        style::label().apply_to("Downgrade:"),
        pb.downgrade
    );
    println!(
        "  {} {}",
        style::label().apply_to("SPL downgrade:"),
        pb.spl_downgrade
    );
    println!(
        "  {} {}",
        style::label().apply_to("Retrofit dynamic partitions:"),
        pb.retrofit_dynamic_partitions
    );
    println!(
        "  {} {}",
        style::label().apply_to("Required cache:"),
        pb.required_cache
    );

    if let Some(pre) = &pb.precondition {
        println!("\n  {}", style::label().apply_to("Precondition:"));
        print_device_state(pre, "    ");
    }
    if let Some(post) = &pb.postcondition {
        println!("\n  {}", style::label().apply_to("Postcondition:"));
        print_device_state(post, "    ");
    }
    if !pb.property_files.is_empty() {
        println!("\n  {}", style::label().apply_to("Property files:"));
        for (k, v) in &pb.property_files {
            println!("    {} {v}", style::bold().apply_to(format!("{k}:")));
        }
    }
}

fn print_device_state(d: &DeviceState, prefix: &str) {
    if !d.device.is_empty() {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("Devices:"),
            d.device.join(", ")
        );
    }
    if !d.build.is_empty() {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("Builds:"),
            d.build.join(", ")
        );
    }
    if !d.build_incremental.is_empty() {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("Build incremental:"),
            d.build_incremental
        );
    }
    if d.timestamp != 0 {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("Timestamp:"),
            d.timestamp
        );
    }
    if !d.sdk_level.is_empty() {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("SDK level:"),
            d.sdk_level
        );
    }
    if !d.security_patch_level.is_empty() {
        println!(
            "{prefix}{} {}",
            style::label().apply_to("Security patch level:"),
            d.security_patch_level
        );
    }
    for ps in &d.partition_state {
        let detail = if !ps.version.is_empty() {
            format!(" version={}", ps.version)
        } else {
            String::new()
        };
        println!(
            "{prefix}{} {}{detail}",
            style::label().apply_to("Partition:"),
            style::bold().apply_to(&ps.partition_name)
        );
        if !ps.build.is_empty() {
            println!("{prefix}  build: {}", ps.build.join(", "));
        }
    }
}
