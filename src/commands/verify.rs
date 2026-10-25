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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Verified,
    Failed,
    Missing,
    Unsupported,
}

fn verify_one(
    partition: &PartitionUpdate,
    dir: &Path,
    block_size: u32,
    hash_tree: bool,
    fec: bool,
) -> Outcome {
    let name = partition.partition_name.as_str();
    let Some(info) = partition.new_partition_info.as_ref() else {
        style::print_skip(name, "no partition info");
        return Outcome::Unsupported;
    };
    let (Some(hash), Some(size)) = (info.hash.as_ref(), info.size) else {
        style::print_skip(name, "no partition hash");
        return Outcome::Unsupported;
    };
    let path = dir.join(format!("{name}.img"));
    if !path.exists() {
        style::print_skip(name, "file not found");
        return Outcome::Missing;
    }
    // All checks share one read-only file mapping.
    let file = match ReadOnlyFile::open(&path) {
        Ok(file) => file,
        Err(e) => {
            style::print_err(name, format_args!("open: {e}"));
            return Outcome::Failed;
        }
    };
    match verify_partition_file(&file, hash, size) {
        Ok(true) => style::print_ok(name, ""),
        Ok(false) => {
            style::print_fail(name, "SHA256 mismatch");
            return Outcome::Failed;
        }
        Err(e) => {
            style::print_err(name, e);
            return Outcome::Failed;
        }
    }
    if hash_tree
        && (partition.hash_tree_extent.is_some() || partition.hash_tree_data_extent.is_some())
    {
        match verify_hash_tree(&file, partition, block_size) {
            Ok(true) => style::print_ok(name, "hash tree"),
            Ok(false) => {
                style::print_fail(name, "hash tree mismatch");
                return Outcome::Failed;
            }
            Err(e) => {
                style::print_err(name, format_args!("hash tree: {e}"));
                return Outcome::Failed;
            }
        }
    }
    if fec && (partition.fec_extent.is_some() || partition.fec_data_extent.is_some()) {
        match verify_fec(&file, partition, block_size) {
            Ok(true) => style::print_ok(name, "FEC"),
            Ok(false) => {
                style::print_fail(name, "FEC check failed");
                return Outcome::Failed;
            }
            Err(e) => {
                style::print_err(name, format_args!("FEC: {e}"));
                return Outcome::Failed;
            }
        }
    }
    Outcome::Verified
}

#[derive(Default)]
struct Summary {
    verified: usize,
    failed: usize,
    missing: usize,
    unsupported: usize,
}

impl Summary {
    /// Partitions with an image on disk.
    fn checked(&self) -> usize {
        self.verified + self.failed
    }
}

fn summarize(outcomes: &[Outcome]) -> Summary {
    let mut summary = Summary::default();
    for outcome in outcomes {
        match outcome {
            Outcome::Verified => summary.verified += 1,
            Outcome::Failed => summary.failed += 1,
            Outcome::Missing => summary.missing += 1,
            Outcome::Unsupported => summary.unsupported += 1,
        }
    }
    summary
}

/// Missing images only fail when the partition was named explicitly; a directory
/// with nothing to verify always fails.
fn validate(summary: &Summary, explicit: bool, dir: &Path) -> Result<()> {
    if summary.failed > 0 {
        anyhow::bail!("verification failed for {} partition(s)", summary.failed);
    }
    if explicit && summary.missing > 0 {
        anyhow::bail!(
            "missing images for {} partition(s) in '{}'",
            summary.missing,
            dir.display()
        );
    }
    if summary.verified == 0 {
        anyhow::bail!("no partition images found in '{}'", dir.display());
    }
    Ok(())
}

pub fn run(args: VerifyArgs, insecure: bool, user_agent: Option<&str>) -> Result<()> {
    let start = Instant::now();
    let payload = input::open(&args.input, insecure, user_agent)?;
    let block_size = payload.block_size();
    let explicit = args
        .partitions
        .as_ref()
        .is_some_and(|names| !names.is_empty());
    let partition_names = args.partitions.unwrap_or_default();
    let partitions = payload.selected_partitions(&partition_names);
    println!(
        "{} {} partitions...",
        style::label().apply_to("Verifying"),
        partitions.len()
    );
    let outcomes: Vec<Outcome> = partitions
        .par_iter()
        .map(|p| verify_one(p, &args.dir, block_size, args.hash_tree, args.fec))
        .collect();
    let summary = summarize(&outcomes);
    let mut label = format!(
        "{}/{} partitions verified",
        summary.verified,
        summary.checked()
    );
    if summary.missing > 0 {
        label.push_str(&format!(", {} missing", summary.missing));
    }
    if summary.unsupported > 0 {
        label.push_str(&format!(", {} unsupported", summary.unsupported));
    }
    let elapsed = start.elapsed();
    println!(
        "\n{} {}",
        style::success().apply_to(format!("{label} in")),
        style::success().bold().apply_to(format!("{elapsed:.2?}"))
    );
    validate(&summary, explicit, &args.dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_images_pass_when_nothing_was_named() {
        let summary = summarize(&[Outcome::Verified, Outcome::Missing]);
        assert!(validate(&summary, false, Path::new("out")).is_ok());
    }

    #[test]
    fn missing_images_fail_when_named() {
        let summary = summarize(&[Outcome::Verified, Outcome::Missing]);
        let err = validate(&summary, true, Path::new("out")).unwrap_err();
        assert_eq!(err.to_string(), "missing images for 1 partition(s) in 'out'");
    }

    #[test]
    fn failed_checks_fail() {
        let summary = summarize(&[Outcome::Verified, Outcome::Failed]);
        assert!(validate(&summary, false, Path::new("out")).is_err());
    }

    #[test]
    fn empty_directory_fails() {
        let summary = summarize(&[Outcome::Missing, Outcome::Unsupported]);
        let err = validate(&summary, false, Path::new("out")).unwrap_err();
        assert!(err.to_string().starts_with("no partition images found"));
    }
}
