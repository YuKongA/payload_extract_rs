use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::input;
use crate::style;

#[derive(Args)]
pub struct ListArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
    pub input: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Show SHA256 hash for each partition
    #[arg(short = 'H', long)]
    pub hash: bool,
}

#[derive(Serialize)]
struct PartitionEntry {
    name: String,
    size: u64,
    operations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

pub fn run(args: ListArgs, insecure: bool, user_agent: Option<&str>) -> Result<()> {
    let payload = input::open(&args.input, insecure, user_agent)?;
    let partitions = payload.partitions();

    let entries: Vec<PartitionEntry> = partitions
        .iter()
        .map(|p| {
            let info = p.new_partition_info.as_ref();
            let size = info.and_then(|i| i.size).unwrap_or(0);
            let hash = if args.hash {
                info.and_then(|i| i.hash.as_ref()).map(hex::encode)
            } else {
                None
            };
            PartitionEntry {
                name: p.partition_name.clone(),
                size,
                operations: p.operations.len(),
                hash,
            }
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else if args.hash {
        println!(
            "{:<25} {:>12} {:>6}  {}",
            style::label().apply_to("PARTITION"),
            style::label().apply_to("SIZE"),
            style::label().apply_to("OPS"),
            style::label().apply_to("SHA256")
        );
        println!("{}", style::dim().apply_to("-".repeat(110)));
        for entry in &entries {
            println!(
                "{:<25} {:>12} {:>6}  {}",
                style::bold().apply_to(&entry.name),
                style::format_size(entry.size),
                entry.operations,
                entry.hash.as_deref().unwrap_or("-")
            );
        }
    } else {
        println!(
            "{:<25} {:>12} {:>6}",
            style::label().apply_to("PARTITION"),
            style::label().apply_to("SIZE"),
            style::label().apply_to("OPS")
        );
        println!("{}", style::dim().apply_to("-".repeat(46)));
        for entry in &entries {
            println!(
                "{:<25} {:>12} {:>6}",
                style::bold().apply_to(&entry.name),
                style::format_size(entry.size),
                entry.operations
            );
        }
    }
    println!(
        "{}",
        style::dim().apply_to("-".repeat(if args.hash { 110 } else { 46 }))
    );
    println!(
        "{} {} partitions",
        style::label().apply_to("Total:"),
        entries.len()
    );

    Ok(())
}
