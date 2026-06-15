use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use rayon::prelude::*;

use crate::extract::verify::{verify_fec, verify_hash_tree, verify_partition};
use crate::input;
use crate::style;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
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

    let results: Vec<(&str, bool)> = partitions
        .par_iter()
        .filter_map(|p| {
            let name = p.partition_name.as_str();
            let info = p.new_partition_info.as_ref()?;
            let hash = info.hash.as_ref()?;
            let size = info.size?;
            let path = args.dir.join(format!("{name}.img"));

            if !path.exists() {
                style::print_skip(name, "file not found");
                return Some((name, false));
            }

            // SHA256 partition verification
            match verify_partition(&path, hash, size) {
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

            // Hash tree and FEC verification share the same mmap
            let needs_mmap = (args.hash_tree && p.hash_tree_extent.is_some())
                || (args.fec && p.fec_extent.is_some());

            if needs_mmap {
                let file = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        style::print_err(name, format_args!("open: {e}"));
                        return Some((name, false));
                    }
                };
                let mmap = match unsafe { memmap2::Mmap::map(&file) } {
                    Ok(m) => m,
                    Err(e) => {
                        style::print_err(name, format_args!("mmap: {e}"));
                        return Some((name, false));
                    }
                };

                if args.hash_tree && p.hash_tree_extent.is_some() {
                    match verify_hash_tree(&mmap, p, block_size) {
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

                if args.fec && p.fec_extent.is_some() {
                    match verify_fec(&mmap, p, block_size) {
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
            }

            Some((name, true))
        })
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
