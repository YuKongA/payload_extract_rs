use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;

use crate::extract::{self, ExtractConfig};
use crate::input;
use crate::style;

#[derive(Args)]
pub struct ExtractArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
    pub input: String,

    /// Output directory
    #[arg(short, long, default_value = "output")]
    pub output: PathBuf,

    /// Comma-separated partition names to include (empty = all)
    #[arg(short, long, value_delimiter = ',')]
    pub partitions: Option<Vec<String>>,

    /// Comma-separated partition names to exclude
    #[arg(short = 'x', long, value_delimiter = ',')]
    pub exclude: Option<Vec<String>>,

    /// Source directory for delta/incremental OTA (old partition images)
    #[arg(short, long)]
    pub source_dir: Option<String>,

    /// Output config file: one line per partition as `partition_name:/path/to/output`
    #[arg(long)]
    pub out_config: Option<PathBuf>,

    /// Number of threads (0 = auto-detect)
    #[arg(short = 'j', long, default_value = "0")]
    pub threads: usize,

    /// Verify SHA256 hash of each operation's data
    #[arg(short, long)]
    pub verify: bool,

    /// Quiet mode (no progress bars)
    #[arg(short, long)]
    pub quiet: bool,

    /// Compute and write back dm-verity hash tree and FEC data after extraction.
    /// Optionally specify comma-separated partition names to limit scope.
    #[arg(long, value_delimiter = ',', num_args = 0.., require_equals = true, default_missing_value = "")]
    pub verify_update: Option<Vec<String>>,
}

pub fn run(args: ExtractArgs, insecure: bool, user_agent: Option<&str>) -> Result<()> {
    let start = Instant::now();

    // Parse output config if provided
    let out_config = if let Some(ref config_path) = args.out_config {
        Some(parse_out_config(config_path)?)
    } else {
        None
    };

    // For HTTP URLs, we need to know partition names BEFORE opening
    // so we can do selective range downloads
    let pre_partition_names: Vec<String> = match (&args.partitions, &args.exclude) {
        (Some(inc), _) => inc.clone(),
        // For exclude mode or all, pass empty (handled after manifest parse)
        _ => Vec::new(),
    };

    if !args.quiet {
        style::log("Opening payload", &args.input);
    }

    // HTTP temp file goes in the output dir: avoids tmpfs (which would defeat
    // the on-disk memory bound) and is guaranteed writable.
    let open_opts = input::OpenOptions {
        insecure,
        user_agent: user_agent.map(str::to_owned),
        download_progress: None,
        temp_dir: Some(args.output.clone()),
    };
    let payload = input::open_for_extract_with(&args.input, &pre_partition_names, &open_opts)?;

    if !args.quiet {
        let partitions = payload.partitions();
        style::log(
            "Payload",
            format_args!(
                "version {}, block_size {}, {} partitions",
                payload.header().version,
                payload.block_size(),
                partitions.len()
            ),
        );
    }

    // Build final partition name list with include/exclude logic
    let partition_names = build_partition_list(
        &payload,
        args.partitions.as_deref(),
        args.exclude.as_deref(),
    );

    let config = ExtractConfig {
        verify_ops: args.verify,
        threads: args.threads,
        quiet: args.quiet,
        source_dir: args.source_dir,
        out_config,
        progress: None,
    };

    extract::extract_partitions(&payload, &args.output, &partition_names, &config)?;

    if !args.quiet {
        style::log_done("Extraction completed in", start.elapsed());
    }

    // Run verify-update (hash tree + FEC write-back) if requested
    if let Some(ref vu_targets) = args.verify_update {
        let vu_start = Instant::now();

        // Determine which partitions to verify-update
        // Filter out empty strings from default_missing_value
        let real_targets: Vec<String> = vu_targets
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect();
        let vu_partitions: Vec<&crate::proto::PartitionUpdate> = if real_targets.is_empty() {
            // --verify-update with no args: all extracted partitions
            payload.selected_partitions(&partition_names)
        } else {
            payload.selected_partitions(&real_targets)
        };

        if !args.quiet {
            style::log(
                "Running verify-update for",
                format_args!("{} partitions...", vu_partitions.len()),
            );
        }

        extract::verify_update::verify_update_partitions(
            &vu_partitions,
            &args.output,
            payload.block_size(),
            args.threads,
            args.quiet,
        )?;

        if !args.quiet {
            style::log_done("Verify-update completed in", vu_start.elapsed());
        }
    }

    Ok(())
}

/// Build partition name list with include/exclude filtering.
fn build_partition_list(
    payload: &crate::payload::PayloadView,
    include: Option<&[String]>,
    exclude: Option<&[String]>,
) -> Vec<String> {
    match (include, exclude) {
        (Some(inc), _) => inc.to_vec(),
        (None, Some(exc)) => payload
            .partitions()
            .iter()
            .map(|p| &p.partition_name)
            .filter(|name| !exc.iter().any(|e| e == *name))
            .cloned()
            .collect(),
        (None, None) => Vec::new(), // empty = all
    }
}

/// Parse output config file. Each line: `partition_name:/path/to/output`
fn parse_out_config(path: &Path) -> Result<HashMap<String, PathBuf>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, path_str)) = line.split_once(':') {
            map.insert(name.trim().to_string(), PathBuf::from(path_str.trim()));
        }
    }
    Ok(map)
}
