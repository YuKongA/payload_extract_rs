use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use rayon::prelude::*;

use crate::extract::verify::{verify_fec, verify_hash_tree, verify_partition_file};
use crate::input;
use crate::proto::PartitionUpdate;
use crate::storage::ReadOnlyFile;
use crate::style;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to payload.bin or a local OTA ZIP (HTTP URLs require native HTTP support)
    pub input: String,

    /// Directory containing extracted .img files
    #[arg(short, long, default_value = "output")]
    pub dir: PathBuf,

    /// Comma-separated partition names (empty = all)
    #[arg(short, long, value_delimiter = ',')]
    pub partitions: Option<Vec<String>>,

    /// Also verify dm-verity hash tree
    #[arg(long)]
    pub hash_tree: bool,

    /// Also verify FEC (Forward Error Correction) data
    #[arg(long)]
    pub fec: bool,
}

fn verify_one<'a>(
    partition: &'a PartitionUpdate,
    dir: &Path,
    block_size: u32,
    hash_tree: bool,
    fec: bool,
) -> Option<(&'a str, bool)> {
    let name = partition.partition_name.as_str();
    let info = partition.new_partition_info.as_ref()?;
    let hash = info.hash.as_ref()?;
    let size = info.size?;
    let path = dir.join(format!("{name}.img"));
    if !path.exists() {
        style::print_skip(name, "file not found");
        return Some((name, false));
    }
    // All checks share one read-only file mapping.
    let file = match ReadOnlyFile::open(&path) {
        Ok(file) => file,
        Err(e) => {
            style::print_err(name, format_args!("open: {e}"));
            return Some((name, false));
        }
    };
    match verify_partition_file(&file, hash, size) {
        Ok(true) => style::print_ok(name, ""),
        Ok(false) => {
            style::print_fail(name, "SHA256 mismatch");
            return Some((name, false));
        }
        Err(e) => {
            style::print_err(name, e);
            return Some((name, false));
        }
    }
    if hash_tree && (partition.hash_tree_extent.is_some() || partition.hash_tree_data_extent.is_some()) {
        match verify_hash_tree(&file, partition, block_size) {
            Ok(true) => style::print_ok(name, "hash tree"),
            Ok(false) => {
                style::print_fail(name, "hash tree mismatch");
                return Some((name, false));
            }
            Err(e) => {
                style::print_err(name, format_args!("hash tree: {e}"));
                return Some((name, false));
            }
        }
    }
    if fec && (partition.fec_extent.is_some() || partition.fec_data_extent.is_some()) {
        match verify_fec(&file, partition, block_size) {
            Ok(true) => style::print_ok(name, "FEC"),
            Ok(false) => {
                style::print_fail(name, "FEC check failed");
                return Some((name, false));
            }
            Err(e) => {
                style::print_err(name, format_args!("FEC: {e}"));
                return Some((name, false));
            }
        }
    }
    Some((name, true))
}

pub fn run(args: VerifyArgs, insecure: bool, user_agent: Option<&str>) -> Result<()> {
    let start = Instant::now();
    let payload = input::open(&args.input, insecure, user_agent)?;
    let block_size = payload.block_size();
    let partition_names = args.partitions.unwrap_or_default();
    let partitions = payload.selected_partitions(&partition_names);
    println!(
        "{} {} partitions...",
        style::label().apply_to("Verifying"),
        partitions.len()
    );
    let results: Vec<(&str, bool)> = partitions.par_iter()
        .filter_map(|p| verify_one(p, &args.dir, block_size, args.hash_tree, args.fec))
        .collect();
    let passed = results.iter().filter(|(_, ok)| *ok).count();
    let total = results.len();
    let elapsed = start.elapsed();
    println!(
        "\n{} {}",
        style::success().apply_to(format!("{passed}/{total} partitions verified in")),
        style::success().bold().apply_to(format!("{elapsed:.2?}"))
    );
    if passed != total {
        anyhow::bail!("verification failed for {} partition(s)", total - passed);
    }
    Ok(())
}
