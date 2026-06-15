pub mod local;
pub mod zip_input;

#[cfg(feature = "http")]
pub mod http;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use memmap2::Mmap;

use crate::ota_metadata::OtaMetadataData;
use crate::payload::PayloadView;

pub(crate) const ZIP_MAGIC: &[u8; 4] = &[0x50, 0x4B, 0x03, 0x04];

/// Progress callback: `(current, total)`. Units depend on context — bytes for
/// HTTP download, completed operations for extraction. Invoked from worker
/// threads / async tasks, so it must be `Send + Sync`.
pub type ProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Options for opening a payload for extraction. Defaults match the legacy
/// `open_for_extract` (no progress callback, system temp dir).
#[derive(Default, Clone)]
pub struct OpenOptions {
    /// Skip TLS certificate verification for HTTPS URLs.
    pub insecure: bool,
    /// Override the HTTP `User-Agent` header.
    pub user_agent: Option<String>,
    /// Invoked ~10x/s during HTTP download with `(downloaded_bytes, total_bytes)`.
    /// Never fires for local files (no download phase).
    pub download_progress: Option<ProgressCallback>,
    /// Directory for the HTTP compact temp file (default: [`std::env::temp_dir`]).
    /// Set to the output dir to avoid tmpfs and guarantee a writable location
    /// (required on Android).
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

/// Open a payload for extraction. For HTTP URLs, selectively downloads
/// only the operation data needed for the specified partitions.
/// If `partition_names` is empty, downloads the entire payload.
///
/// Back-compat wrapper over [`open_for_extract_with`] with default options.
/// Kept for external consumers (e.g. the GUI JNI layer); the CLI uses `_with`.
#[allow(dead_code)]
pub fn open_for_extract(
    input: &str,
    partition_names: &[String],
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<PayloadView> {
    let opts = OpenOptions {
        insecure,
        user_agent: user_agent.map(str::to_owned),
        ..Default::default()
    };
    open_for_extract_with(input, partition_names, &opts)
}

/// Open a payload for extraction with explicit [`OpenOptions`] — lets callers
/// observe download progress and control the temp-file location.
pub fn open_for_extract_with(
    input: &str,
    partition_names: &[String],
    opts: &OpenOptions,
) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_extract(input, partition_names, opts);
    }

    let _ = (partition_names, opts);
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
