pub mod local;
pub mod zip_input;
#[cfg(any(test, feature = "http"))]
pub(crate) mod ranges;

#[cfg(feature = "http")]
pub mod http;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use memmap2::Mmap;

use crate::ota_metadata::OtaMetadataData;
use crate::payload::PayloadView;
use crate::proto::PartitionUpdate;

pub(crate) const ZIP_MAGIC: &[u8; 4] = &[0x50, 0x4B, 0x03, 0x04];

/// HTTP bytes or completed operations. Native callbacks may run on worker threads.
pub type ProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Extraction input options, including HTTP progress and temporary storage.
#[derive(Default, Clone)]
pub struct OpenOptions {
    /// Skip TLS certificate verification for HTTPS URLs.
    pub insecure: bool,
    /// Override the HTTP `User-Agent` header.
    pub user_agent: Option<String>,
    /// Invoked ~10x/s during HTTP download with `(downloaded_bytes, total_bytes)`.
    /// Never fires for local files (no download phase).
    pub download_progress: Option<ProgressCallback>,
    /// HTTP cache directory (default: system temp); use output on Android to avoid tmpfs.
    pub temp_dir: Option<PathBuf>,
}

/// Open a payload from a file path or URL and return a PayloadView.
/// For HTTP URLs, only downloads header + manifest (sufficient for list/metadata).
pub fn open(input: &str, insecure: bool, user_agent: Option<&str>) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_metadata(input, insecure, user_agent);
    }

    let _ = (insecure, user_agent);
    open_local_file(input)
}

/// Partition selection, resolved against the manifest once it is available.
#[derive(Clone, Debug, Default)]
pub enum PartitionFilter {
    #[default]
    All,
    Include(Vec<String>),
    Exclude(Vec<String>),
}

impl PartitionFilter {
    /// Partitions matching this filter; an explicit filter matching nothing is an error.
    pub fn select<'a>(&self, partitions: &'a [PartitionUpdate]) -> Result<Vec<&'a PartitionUpdate>> {
        let selected: Vec<&PartitionUpdate> = partitions
            .iter()
            .filter(|partition| match self {
                Self::All => true,
                Self::Include(names) => names.iter().any(|n| n == &partition.partition_name),
                Self::Exclude(names) => !names.iter().any(|n| n == &partition.partition_name),
            })
            .collect();
        if selected.is_empty() {
            match self {
                Self::All => bail!("payload has no partitions"),
                Self::Include(_) => bail!("none of the specified partitions found"),
                Self::Exclude(_) => bail!("all partitions excluded"),
            }
        }
        Ok(selected)
    }
}

/// Open with default options.
pub fn open_for_extract(
    input: &str,
    filter: &PartitionFilter,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<PayloadView> {
    let opts = OpenOptions {
        insecure,
        user_agent: user_agent.map(str::to_owned),
        ..Default::default()
    };
    open_for_extract_with(input, filter, &opts)
}

/// Open with explicit options; `filter` decides which operations are downloaded.
pub fn open_for_extract_with(
    input: &str,
    filter: &PartitionFilter,
    opts: &OpenOptions,
) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_extract(input, filter, opts);
    }

    let _ = (filter, opts);
    open_local_file(input)
}

/// Read the OTA metadata files (META-INF/com/android/metadata and metadata.pb)
/// from an OTA ZIP archive (local file or HTTP URL).
pub fn read_ota_metadata(
    input: &str,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<OtaMetadataData> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::read_ota_metadata_http(input, insecure, user_agent);
    }

    let _ = (insecure, user_agent);
    let path = Path::new(input);
    let file = std::fs::File::open(path).with_context(|| format!("failed to open '{}'", input))?;
    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("failed to mmap '{}'", input))?;

    if mmap.len() < 4 || &mmap[0..4] != ZIP_MAGIC {
        bail!("input is not an OTA ZIP archive");
    }
    zip_input::read_ota_metadata_from_mmap(&mmap).context("failed to read OTA metadata")
}

fn open_local_file(input: &str) -> Result<PayloadView> {
    let path = Path::new(input);
    let file = std::fs::File::open(path).with_context(|| format!("failed to open '{}'", input))?;

    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("failed to mmap '{}'", input))?;

    // Detect format by magic bytes
    if mmap.len() >= 4 && &mmap[0..4] == ZIP_MAGIC {
        zip_input::open_zip(mmap).context("failed to open ZIP payload")
    } else {
        local::open_local(mmap).context("failed to open raw payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partitions(names: &[&str]) -> Vec<PartitionUpdate> {
        names
            .iter()
            .map(|name| PartitionUpdate {
                partition_name: (*name).to_string(),
                ..Default::default()
            })
            .collect()
    }

    fn names<'a>(selected: &[&'a PartitionUpdate]) -> Vec<&'a str> {
        selected.iter().map(|p| p.partition_name.as_str()).collect()
    }

    #[test]
    fn all_selects_every_partition() {
        let all = partitions(&["boot", "system"]);
        let selected = PartitionFilter::All.select(&all).unwrap();
        assert_eq!(names(&selected), ["boot", "system"]);
    }

    #[test]
    fn include_keeps_named_partitions_in_manifest_order() {
        let all = partitions(&["boot", "system", "vendor"]);
        let filter = PartitionFilter::Include(vec!["vendor".into(), "boot".into()]);
        let selected = filter.select(&all).unwrap();
        assert_eq!(names(&selected), ["boot", "vendor"]);
    }

    #[test]
    fn exclude_drops_named_partitions() {
        let all = partitions(&["boot", "system", "vendor"]);
        let filter = PartitionFilter::Exclude(vec!["system".into()]);
        let selected = filter.select(&all).unwrap();
        assert_eq!(names(&selected), ["boot", "vendor"]);
    }

    #[test]
    fn filters_matching_nothing_are_errors() {
        let all = partitions(&["boot"]);
        let missing = PartitionFilter::Include(vec!["nope".into()]);
        assert!(missing.select(&all).is_err());
        let empty = PartitionFilter::Exclude(vec!["boot".into()]);
        assert!(empty.select(&all).is_err());
    }
}
