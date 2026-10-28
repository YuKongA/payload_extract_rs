use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use prost::Message;

use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;
use crate::payload::header::{HEADER_SIZE, MAGIC, PayloadHeader};
use crate::proto::DeltaArchiveManifest;
use crate::storage::write_all_at;
use crate::style;

use super::ZIP_MAGIC;
use super::ranges::plan_compact;
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CD_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];
const MAX_DOWNLOAD_CHUNK: u64 = 32 * 1024 * 1024;
const DEFAULT_CONCURRENCY: usize = 4;

const DEFAULT_USER_AGENT: &str =
    "Dalvik/2.1.0 (Linux; V; Android 16; Android Build/BP2A.250605.015)";

fn build_client(
    insecure: bool,
    user_agent: Option<&str>,
    max_concurrency: usize,
) -> Result<reqwest::Client> {
    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );

    #[allow(unused_mut)]
    let mut builder = reqwest::Client::builder()
        .default_headers(default_headers)
        .danger_accept_invalid_certs(insecure)
        .user_agent(user_agent.unwrap_or(DEFAULT_USER_AGENT))
        .timeout(Duration::from_secs(3600))
        .connect_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(max_concurrency.max(4))
        .tcp_nodelay(true)
        .redirect(reqwest::redirect::Policy::limited(10));

    #[cfg(feature = "http-rustls")]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|cert| reqwest::tls::Certificate::from_der(cert.as_ref()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse webpki root certs")?;
        builder = builder.tls_certs_only(roots);
    }

    builder.build().context("failed to build HTTP client")
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")
}

/// Require exact bounds; return `None` when the total size is unknown.
fn validate_content_range(
    headers: &reqwest::header::HeaderMap,
    start: u64,
    end: u64,
) -> Result<Option<u64>> {
    let value = headers
        .get(reqwest::header::CONTENT_RANGE)
        .context("missing Content-Range header")?
        .to_str()
        .context("invalid Content-Range header")?;
    let (unit, range) = value
        .split_once(' ')
        .context("invalid Content-Range header")?;
    ensure!(
        unit.eq_ignore_ascii_case("bytes"),
        "invalid Content-Range unit: {value}"
    );
    let (bounds, total) = range
        .split_once('/')
        .context("invalid Content-Range header")?;
    let (first, last) = bounds
        .split_once('-')
        .context("invalid Content-Range header")?;
    let first: u64 = first.parse().context("invalid Content-Range start")?;
    let last: u64 = last.parse().context("invalid Content-Range end")?;
    ensure!(
        first == start && last == end,
        "unexpected Content-Range {value}; expected bytes {start}-{end}"
    );
    if total == "*" {
        Ok(None)
    } else {
        let total: u64 = total.parse().context("invalid Content-Range total")?;
        ensure!(total > last, "invalid Content-Range total: {value}");
        Ok(Some(total))
    }
}

fn range_end(offset: u64, length: u64) -> Result<u64> {
    ensure!(length > 0, "zero-length HTTP range");
    offset
        .checked_add(length - 1)
        .context("HTTP range overflows")
}

/// Buffer small ranges; stream large downloads via [`range_download_to_target`].
async fn range_download(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    use futures::StreamExt;

    let end = range_end(offset, length)?;
    for attempt in 0..=3u32 {
        let resp = match client
            .get(url)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if attempt == 3 {
                    return Err(e).context("max retries exceeded");
                }
                tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
                continue;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            validate_content_range(resp.headers(), offset, end)?;
            // Stream into the final buffer to avoid a full-body copy.
            let mut buf = Vec::with_capacity(length as usize);
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("stream error")?;
                ensure!(
                    (chunk.len() as u64) <= length - buf.len() as u64,
                    "HTTP range response exceeds requested length"
                );
                buf.extend_from_slice(&chunk);
            }
            ensure!(
                buf.len() as u64 == length,
                "short HTTP range response: got {} of {length} bytes",
                buf.len()
            );
            return Ok(buf);
        }

        if status == reqwest::StatusCode::OK {
            // 200 fallback: stream only requested bytes to prevent OOM
            let mut buf = Vec::with_capacity(length as usize);
            let mut stream = resp.bytes_stream();
            let mut to_skip = offset;
            let mut to_read = length as usize;

            while to_read > 0 {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let chunk = &chunk[..];
                        if to_skip > 0 {
                            let skip = (to_skip as usize).min(chunk.len());
                            to_skip -= skip as u64;
                            let remaining_chunk = &chunk[skip..];
                            if !remaining_chunk.is_empty() {
                                let take = remaining_chunk.len().min(to_read);
                                buf.extend_from_slice(&remaining_chunk[..take]);
                                to_read -= take;
                            }
                        } else {
                            let take = chunk.len().min(to_read);
                            buf.extend_from_slice(&chunk[..take]);
                            to_read -= take;
                        }
                    }
                    Some(Err(e)) => return Err(e).context("stream error"),
                    None => break,
                }
            }
            ensure!(to_read == 0, "short HTTP response: missing {to_read} of {length} bytes");
            return Ok(buf);
        }

        if attempt == 3 {
            bail!("HTTP {status} for range {offset}-{end}");
        }
        tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
    }
    unreachable!()
}

async fn detect_payload_offset(client: &reqwest::Client, url: &str) -> Result<u64> {
    let (total_size, head) = fetch_total_size_and_head(client, url).await?;

    if head.len() >= 4 && &head[..4] == MAGIC {
        return Ok(0);
    }
    if head.len() < 4 || &head[..4] != ZIP_MAGIC {
        bail!(
            "unrecognized format (magic: {:02x?})",
            &head[..4.min(head.len())]
        );
    }

    eprintln!(
        "{} ({})...",
        style::label().apply_to("Parsing remote ZIP"),
        style::format_size(total_size)
    );
    let cd = fetch_zip_cd(client, url, total_size).await?;
    let entry = find_cd_entry(&cd, "payload.bin").context("payload.bin not found in remote ZIP")?;

    let lfh = range_download(client, url, entry.local_off, 30).await?;
    let n = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
    let e = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
    Ok(entry.local_off + 30 + n + e)
}

pub fn open_http_metadata(
    url: &str,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<PayloadView> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure, user_agent, DEFAULT_CONCURRENCY)?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len = (HEADER_SIZE as u64)
            .checked_add(header.manifest_size)
            .and_then(|length| length.checked_add(header.metadata_signature_size as u64))
            .context("payload metadata length overflows")?;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len).await?;

        Ok(PayloadView::from_memory(meta, HashMap::new())?)
    })
}

pub fn open_http_extract(
    url: &str,
    filter: &super::PartitionFilter,
    opts: &super::OpenOptions,
) -> Result<PayloadView> {
    use std::sync::Arc;

    let rt = build_runtime()?;
    rt.block_on(async {
        let concurrency = opts.concurrency.unwrap_or(DEFAULT_CONCURRENCY).max(1);
        let client = build_client(opts.insecure, opts.user_agent.as_deref(), concurrency)?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len = (HEADER_SIZE as u64).checked_add(header.manifest_size)
            .and_then(|length| length.checked_add(header.metadata_signature_size as u64))
            .context("payload metadata length overflows")?;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len).await?;

        let manifest = DeltaArchiveManifest::decode(
            &meta[HEADER_SIZE..HEADER_SIZE + header.manifest_size as usize],
        )?;
        let data_offset = meta_len;

        let parts = filter.select(&manifest.partitions)?;

        let mut op_ranges: Vec<(u64, u64)> = Vec::new();
        for p in &parts {
            for op in &p.operations {
                let off = op.data_offset.unwrap_or(0);
                let len = op.data_length.unwrap_or(0);
                if len > 0 {
                    op_ranges.push((off, len));
                }
            }
        }

        if op_ranges.is_empty() {
            return Ok(PayloadView::from_memory(meta, HashMap::new())?);
        }

        let plan = plan_compact(meta_len, op_ranges, None)?;
        let total_data = plan.download_bytes;
        style::log(
            "Selective download",
            format_args!("{} ({} range(s))", style::format_size(total_data), plan.ranges.len()),
        );

        let total_size = plan.total_size;

        let in_memory_limit: u64 = if cfg!(target_pointer_width = "64") {
            1024 * 1024 * 1024
        } else {
            128 * 1024 * 1024
        };
        let in_memory = if total_size <= in_memory_limit {
            if let Some(available) = available_memory() {
                available >= total_size.saturating_add(256 * 1024 * 1024)
            } else {
                true
            }
        } else {
            false
        };

        let (mem_buf, target, named_file) = if in_memory {
            let mut buf = vec![0u8; total_size as usize];
            buf[..meta.len()].copy_from_slice(&meta);
            let target = DownloadTarget::Buffer(SyncBuffer {
                ptr: buf.as_mut_ptr(),
                len: buf.len(),
            });
            (Some(buf), target, None)
        } else {
            let temp_dir = opts
                .temp_dir
                .clone()
                .unwrap_or_else(std::env::temp_dir);
            std::fs::create_dir_all(&temp_dir)
                .with_context(|| format!("failed to create temp dir '{}'", temp_dir.display()))?;
            let named = tempfile::NamedTempFile::new_in(&temp_dir)
                .context("failed to create temp payload file")?;
            named
                .as_file()
                .set_len(total_size)
                .context("failed to size temp payload file")?;
            write_all_at(named.as_file(), &meta, 0).context("temp file write failed")?;
            let file_ref = Arc::new(
                named
                    .as_file()
                    .try_clone()
                    .context("failed to clone temp file handle")?,
            );
            (None, DownloadTarget::File(file_ref), Some(named))
        };
        drop(meta);

        let client = Arc::new(client);
        let url: Arc<str> = Arc::from(url);
        let downloaded = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut handles = Vec::new();
        for range in &plan.ranges {
            let remote_off_base = payload_off
                .checked_add(data_offset)
                .and_then(|offset| offset.checked_add(range.data_offset))
                .context("remote operation offset overflows")?;
            let file_base = range.file_offset;
            let total_len = range.length;

            let mut offset_in_range = 0u64;
            while offset_in_range < total_len {
                let chunk_len = (total_len - offset_in_range).min(MAX_DOWNLOAD_CHUNK);
                let remote_off = remote_off_base + offset_in_range;
                let chunk_file_base = file_base + offset_in_range;
                offset_in_range += chunk_len;

                let client = client.clone();
                let url = url.clone();
                let downloaded = downloaded.clone();
                let sem = sem.clone();
                let target = target.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    range_download_to_target(
                        &client,
                        &url,
                        remote_off,
                        chunk_len,
                        &target,
                        chunk_file_base,
                        &downloaded,
                    )
                    .await
                }));
            }
        }

        let pb = indicatif::ProgressBar::new(total_data);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{prefix:>20} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) [{elapsed_precise}]",
            )
            .unwrap()
            .progress_chars("=> "),
        );
        pb.set_prefix("Downloading");

        // Poll streamed byte counts so progress advances within each range.
        let ticker = {
            let pb = pb.clone();
            let downloaded = downloaded.clone();
            let dl_cb = opts.download_progress.clone();
            tokio::spawn(async move {
                loop {
                    let done = downloaded.load(Ordering::Relaxed);
                    pb.set_position(done);
                    if let Some(cb) = &dl_cb {
                        cb(done, total_data);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };

        for handle in handles {
            handle.await??;
        }
        ticker.abort();
        pb.set_position(total_data);
        pb.finish_and_clear();
        if let Some(cb) = &opts.download_progress {
            cb(total_data, total_data);
        }

        drop(target);
        if let Some(buf) = mem_buf {
            style::log(
                "In-memory",
                format_args!(
                    "{} (meta {} + data {})",
                    style::format_size(total_size),
                    style::format_size(meta_len),
                    style::format_size(total_data),
                ),
            );
            Ok(PayloadView::from_memory(buf, plan.remap)?)
        } else {
            let named = named_file.unwrap();
            style::log(
                "Temp file",
                format_args!(
                    "{} (meta {} + data {})",
                    style::format_size(total_size),
                    style::format_size(meta_len),
                    style::format_size(total_data),
                ),
            );
            let mmap = unsafe { memmap2::Mmap::map(named.as_file()) }
                .context("failed to mmap temp payload file")?;
            Ok(PayloadView::from_mmap_compact(mmap, plan.remap, Box::new(named))?)
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn available_memory() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(windows)]
fn available_memory() -> Option<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    unsafe extern "system" {
        fn GlobalMemoryStatusEx(stat: *mut MemoryStatusEx) -> i32;
    }

    let mut stat = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };
    if unsafe { GlobalMemoryStatusEx(&mut stat) } != 0 {
        Some(stat.avail_phys)
    } else {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn available_memory() -> Option<u64> {
    None
}

#[derive(Clone, Copy)]
struct SyncBuffer {
    ptr: *mut u8,
    len: usize,
}
unsafe impl Send for SyncBuffer {}
unsafe impl Sync for SyncBuffer {}

#[derive(Clone)]
enum DownloadTarget {
    File(Arc<std::fs::File>),
    Buffer(SyncBuffer),
}

impl DownloadTarget {
    fn write_at(&self, data: &[u8], offset: u64) -> Result<()> {
        match self {
            Self::File(file) => write_all_at(file, data, offset).context("temp file write failed"),
            Self::Buffer(buf) => {
                let off = usize::try_from(offset).context("offset overflow")?;
                let end = off.checked_add(data.len()).context("buffer overflow")?;
                ensure!(end <= buf.len, "buffer write out of bounds");
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), buf.ptr.add(off), data.len());
                }
                Ok(())
            }
        }
    }
}

/// Stream a range into memory or a file, updating `downloaded` per chunk.
async fn range_download_to_target(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    target: &DownloadTarget,
    file_base: u64,
    downloaded: &AtomicU64,
) -> Result<()> {
    use futures::StreamExt;

    let end = range_end(offset, length)?;
    for attempt in 0..=3u32 {
        let resp = match client
            .get(url)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if attempt == 3 {
                    return Err(e).context("max retries exceeded");
                }
                tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
                continue;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            validate_content_range(resp.headers(), offset, end)?;
            let mut stream = resp.bytes_stream();
            let mut written = 0u64;
            let mut stream_err = None;
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => {
                        ensure!(
                            (chunk.len() as u64) <= length - written,
                            "HTTP range response exceeds requested length"
                        );
                        target.write_at(&chunk, file_base + written)?;
                        written += chunk.len() as u64;
                        downloaded.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        stream_err = Some(e);
                        break;
                    }
                }
            }
            if let Some(e) = stream_err {
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
                    continue;
                }
                return Err(e).context("stream error");
            }
            if written != length {
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
                    continue;
                }
                bail!("short read: got {written} of {length} bytes for range {offset}-{end}");
            }
            return Ok(());
        }

        if status == reqwest::StatusCode::OK {
            // 200 fallback: server ignored Range and returns the whole file.
            let mut stream = resp.bytes_stream();
            let mut to_skip = offset;
            let mut written = 0u64;
            let mut remaining = length;

            while remaining > 0 {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let mut chunk = &chunk[..];
                        if to_skip > 0 {
                            let skip = (to_skip as usize).min(chunk.len());
                            to_skip -= skip as u64;
                            chunk = &chunk[skip..];
                        }
                        if chunk.is_empty() {
                            continue;
                        }
                        let take = (chunk.len() as u64).min(remaining) as usize;
                        target.write_at(&chunk[..take], file_base + written)?;
                        written += take as u64;
                        remaining -= take as u64;
                        downloaded.fetch_add(take as u64, Ordering::Relaxed);
                    }
                    Some(Err(e)) => return Err(e).context("stream error"),
                    None => break,
                }
            }
            if remaining != 0 {
                bail!("short read: missing {remaining} of {length} bytes for range {offset}-{end}");
            }
            return Ok(());
        }

        if attempt == 3 {
            bail!("HTTP {status} for range {offset}-{end}");
        }
        tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
    }
    unreachable!()
}

/// Fetch META-INF/com/android/metadata and metadata.pb from a remote OTA ZIP.
/// The two entries are downloaded concurrently after a single CD fetch.
pub fn read_ota_metadata_http(
    url: &str,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<OtaMetadataData> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure, user_agent, DEFAULT_CONCURRENCY)?;
        let (total_size, head) = fetch_total_size_and_head(&client, url).await?;
        if head.len() < 4 || &head[..4] != ZIP_MAGIC {
            bail!(
                "URL is not an OTA ZIP (magic: {:02x?})",
                &head[..4.min(head.len())]
            );
        }
        let cd = fetch_zip_cd(&client, url, total_size).await?;

        let (text_bytes, pb_bytes) = tokio::try_join!(
            download_stored_zip_entry(&client, url, &cd, ota_metadata::text_entry_name(), total_size),
            download_stored_zip_entry(&client, url, &cd, ota_metadata::pb_entry_name(), total_size),
        )?;

        let mut data = OtaMetadataData::default();
        if let Some(b) = text_bytes {
            data.text = Some(ota_metadata::parse_text(&String::from_utf8_lossy(&b)));
        }
        if let Some(b) = pb_bytes {
            data.pb = Some(ota_metadata::parse_pb_bytes(&b)?);
        }
        Ok(data)
    })
}

/// Probe the file size and magic using a four-byte range request.
async fn fetch_total_size_and_head(client: &reqwest::Client, url: &str) -> Result<(u64, Vec<u8>)> {
    let resp = client
        .get(url)
        .header("Range", "bytes=0-3")
        .send()
        .await?
        .error_for_status()?;

    let total_size = if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        validate_content_range(resp.headers(), 0, 3)?
            .context("cannot determine file size from Content-Range")?
    } else {
        resp.content_length()
            .context("server returned no Content-Length")?
    };

    let partial = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
    let head = resp.bytes().await?.to_vec();
    if partial {
        ensure!(head.len() == 4, "invalid HTTP range response length: expected 4, got {}", head.len());
    }
    let head = if head.len() >= 4 {
        head
    } else {
        range_download(client, url, 0, 4).await?
    };
    Ok((total_size, head))
}

/// Locate the EOCD (and optional ZIP64 record) and return the central directory bytes.
async fn fetch_zip_cd(client: &reqwest::Client, url: &str, total_size: u64) -> Result<Vec<u8>> {
    let tail_size = (256 * 1024u64).min(total_size);
    let tail_offset = total_size - tail_size;
    let tail = range_download(client, url, tail_offset, tail_size).await?;

    let eocd_pos = tail
        .windows(4)
        .rposition(|w| w == ZIP_EOCD_SIG)
        .context("EOCD not found")?;

    let is_zip64 = eocd_pos >= 20 && tail[eocd_pos - 20..eocd_pos - 16] == ZIP64_LOCATOR_SIG;

    let (cd_offset, cd_size) = if is_zip64 {
        let locator = &tail[eocd_pos - 20..eocd_pos];
        let z64_off = u64::from_le_bytes(locator[8..16].try_into().unwrap());
        let rec = if z64_off >= tail_offset {
            let i = (z64_off - tail_offset) as usize;
            tail[i..i + 56].to_vec()
        } else {
            range_download(client, url, z64_off, 56).await?
        };
        (
            u64::from_le_bytes(rec[48..56].try_into().unwrap()),
            u64::from_le_bytes(rec[40..48].try_into().unwrap()),
        )
    } else {
        let eocd = &tail[eocd_pos..];
        (
            u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as u64,
            u32::from_le_bytes(eocd[12..16].try_into().unwrap()) as u64,
        )
    };

    let cd = if cd_offset >= tail_offset {
        let i = (cd_offset - tail_offset) as usize;
        tail[i..i + cd_size as usize].to_vec()
    } else {
        range_download(client, url, cd_offset, cd_size).await?
    };
    Ok(cd)
}

#[derive(Debug)]
struct CdEntry {
    local_off: u64,
    compressed_size: u64,
    compression: u16,
    name_len: u16,
}

/// Linear scan of the central directory for an entry by name.
/// Resolves ZIP64 sentinel fields from the per-entry extra block.
fn find_cd_entry(cd: &[u8], target: &str) -> Option<CdEntry> {
    let mut pos = 0usize;
    while pos + 46 <= cd.len() {
        if cd[pos..pos + 4] != ZIP_CD_SIG {
            break;
        }
        let comp_method = u16::from_le_bytes(cd[pos + 10..pos + 12].try_into().unwrap());
        let csize_field = u32::from_le_bytes(cd[pos + 20..pos + 24].try_into().unwrap());
        let usize_field = u32::from_le_bytes(cd[pos + 24..pos + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes(cd[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(cd[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(cd[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_off_field = u32::from_le_bytes(cd[pos + 42..pos + 46].try_into().unwrap());

        if pos + 46 + name_len > cd.len() {
            break;
        }
        let name = std::str::from_utf8(&cd[pos + 46..pos + 46 + name_len]).unwrap_or("");

        if name == target {
            let extra = &cd[pos + 46 + name_len..pos + 46 + name_len + extra_len];
            let (local_off, csize, _usize) =
                resolve_zip64_fields(local_off_field, csize_field, usize_field, extra);
            return Some(CdEntry {
                local_off,
                compressed_size: csize,
                compression: comp_method,
                name_len: name_len as u16,
            });
        }
        pos += 46 + name_len + extra_len + comment_len;
    }
    None
}

/// Download a STORED CD entry's raw bytes. A single optimistic range request
/// covers LFH + name + extra + payload; a fallback request handles the rare
/// case where the LFH extra field exceeds `LFH_EXTRA_HEADROOM`.
async fn download_stored_zip_entry(
    client: &reqwest::Client,
    url: &str,
    cd: &[u8],
    target: &str,
    total_size: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(entry) = find_cd_entry(cd, target) else {
        return Ok(None);
    };
    if entry.compression != 0 {
        bail!(
            "{target} entry is compressed (method {}); only STORED is supported",
            entry.compression
        );
    }

    const LFH_EXTRA_HEADROOM: u64 = 1024;
    let optimistic = 30 + entry.name_len as u64 + LFH_EXTRA_HEADROOM + entry.compressed_size;
    let available = total_size
        .checked_sub(entry.local_off)
        .context("ZIP entry offset exceeds archive length")?;
    let buf = range_download(client, url, entry.local_off, optimistic.min(available)).await?;
    if buf.len() < 30 {
        bail!("LFH truncated for {target}");
    }
    let n = u16::from_le_bytes(buf[26..28].try_into().unwrap()) as usize;
    let e = u16::from_le_bytes(buf[28..30].try_into().unwrap()) as usize;
    let data_off = 30 + n + e;
    let data_end = data_off + entry.compressed_size as usize;

    if data_end <= buf.len() {
        return Ok(Some(buf[data_off..data_end].to_vec()));
    }

    let abs_data_off = entry.local_off + data_off as u64;
    let data = range_download(client, url, abs_data_off, entry.compressed_size).await?;
    Ok(Some(data))
}

/// Resolve potential ZIP64 sentinel values in a CD entry by reading the extra field.
/// The ZIP64 extended-info (tag 0x0001) packs uncompressed size, compressed size, then
/// local header offset, but only the fields whose 32-bit values are 0xFFFFFFFF are stored.
fn resolve_zip64_fields(
    local_off_field: u32,
    csize_field: u32,
    usize_field: u32,
    extra: &[u8],
) -> (u64, u64, u64) {
    let mut local_off = local_off_field as u64;
    let mut csize = csize_field as u64;
    let mut usize_ = usize_field as u64;

    if usize_field != 0xFFFFFFFF && csize_field != 0xFFFFFFFF && local_off_field != 0xFFFFFFFF {
        return (local_off, csize, usize_);
    }

    let mut p = 0;
    while p + 4 <= extra.len() {
        let tag = u16::from_le_bytes(extra[p..p + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[p + 2..p + 4].try_into().unwrap()) as usize;
        if tag == 0x0001 && p + 4 + sz <= extra.len() {
            let body = &extra[p + 4..p + 4 + sz];
            let mut q = 0usize;
            if usize_field == 0xFFFFFFFF && q + 8 <= body.len() {
                usize_ = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
                q += 8;
            }
            if csize_field == 0xFFFFFFFF && q + 8 <= body.len() {
                csize = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
                q += 8;
            }
            if local_off_field == 0xFFFFFFFF && q + 8 <= body.len() {
                local_off = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
            }
            break;
        }
        p += 4 + sz;
    }
    (local_off, csize, usize_)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn serve_once(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            let _ = stream.write_all(response);
        });
        (url, server)
    }

    #[test]
    fn partial_reads_reject_bad_ranges_and_lengths() {
        let runtime = build_runtime().unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        runtime.block_on(async {
            for (response, expected) in [
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbcde".as_slice(), true),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-5/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbcde".as_slice(), false),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbcde".as_slice(), false),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nbcdef\r\n0\r\n\r\n".as_slice(), false),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbcd".as_slice(), false),
                (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabcdefghij".as_slice(), true),
            ] {
                let (url, server) = serve_once(response);
                let result = range_download(&client, &url, 1, 4).await;
                if expected {
                    assert_eq!(result.unwrap(), b"bcde");
                } else {
                    assert!(result.is_err());
                }
                server.join().unwrap();
            }
        });
    }

    #[test]
    fn partial_target_write_never_crosses_requested_range() {
        let runtime = build_runtime().unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        runtime.block_on(async {
            for (response, expected) in [
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbcde".as_slice(), true),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-5/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbcde".as_slice(), false),
                (b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nbcdef\r\n0\r\n\r\n".as_slice(), false),
            ] {
                let (url, server) = serve_once(response);
                let mut bytes = [0xaa; 8];
                let target = DownloadTarget::Buffer(SyncBuffer {
                    ptr: bytes.as_mut_ptr(),
                    len: bytes.len(),
                });
                let downloaded = AtomicU64::new(0);
                let result =
                    range_download_to_target(&client, &url, 1, 4, &target, 0, &downloaded).await;
                assert_eq!(result.is_ok(), expected);
                assert_eq!(&bytes[4..], &[0xaa; 4]);
                if expected {
                    assert_eq!(&bytes[..4], b"bcde");
                }
                server.join().unwrap();
            }
        });
    }

    #[test]
    fn zip_size_probe_rejects_wrong_content_range() {
        let runtime = build_runtime().unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let (url, server) = serve_once(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 1-4/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPKxx");
        assert!(runtime.block_on(fetch_total_size_and_head(&client, &url)).is_err());
        server.join().unwrap();
    }

    #[test]
    fn test_available_memory() {
        if let Some(avail) = available_memory() {
            assert!(avail > 0);
        }
    }
}
