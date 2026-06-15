pub mod local;
pub mod zip_input;

#[cfg(feature = "http")]
pub mod http;

use std::path::Path;

use anyhow::{Context, Result, bail};
use memmap2::Mmap;

use crate::ota_metadata::OtaMetadataData;
use crate::payload::PayloadView;

pub(crate) const ZIP_MAGIC: &[u8; 4] = &[0x50, 0x4B, 0x03, 0x04];

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
pub fn open_for_extract(
    input: &str,
    partition_names: &[String],
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_extract(input, partition_names, insecure, user_agent);
    }

    let _ = (partition_names, insecure, user_agent);
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
