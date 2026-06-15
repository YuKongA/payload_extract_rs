use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use prost::Message;

use crate::extract::writer::write_all_at;
use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;
use crate::payload::header::{HEADER_SIZE, MAGIC, PayloadHeader};
use crate::proto::DeltaArchiveManifest;
use crate::style;

use super::ZIP_MAGIC;
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CD_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];

/// Default User-Agent
const DEFAULT_USER_AGENT: &str =
    "Dalvik/2.1.0 (Linux; V; Android 16; Android Build/BP2A.250605.015)";

fn build_client(insecure: bool, user_agent: Option<&str>) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .user_agent(user_agent.unwrap_or(DEFAULT_USER_AGENT))
        .timeout(Duration::from_secs(3600))
        .connect_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(4)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .context("failed to build HTTP client")
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().context("failed to create tokio runtime")
}

/// Download a byte range fully into memory. Used for small reads (header,
/// manifest, ZIP central directory, LFH). Large selective-download ranges go
/// through [`range_download_to_file`] instead, which streams to disk.
async fn range_download(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    use futures::StreamExt;

    let end = offset + length - 1;
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
            // Stream into a pre-sized buffer (one copy, no realloc), avoiding the
            // extra full copy that `resp.bytes().to_vec()` would incur.
            let mut buf = Vec::with_capacity(length as usize);
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("stream error")?;
                buf.extend_from_slice(&chunk);
            }
            return Ok(buf);
        }

        if status.is_success() {
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
        let client = build_client(insecure, user_agent)?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
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
    partition_names: &[String],
    opts: &super::OpenOptions,
) -> Result<PayloadView> {
    use std::sync::Arc;

    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(opts.insecure, opts.user_agent.as_deref())?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len).await?;

        let manifest = DeltaArchiveManifest::decode(
            &meta[HEADER_SIZE..HEADER_SIZE + header.manifest_size as usize],
        )?;
        let data_offset = header.data_offset();

        let parts: Vec<_> = if partition_names.is_empty() {
            manifest.partitions.iter().collect()
        } else {
            manifest
                .partitions
                .iter()
                .filter(|p| partition_names.iter().any(|n| n == &p.partition_name))
                .collect()
        };
        if parts.is_empty() && !partition_names.is_empty() {
            bail!("none of the specified partitions found");
        }

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

        op_ranges.sort_by_key(|r| r.0);
        op_ranges.dedup();

        let merged = merge_ranges(&op_ranges);
        let total_data: u64 = merged.iter().map(|r| r.1).sum();
        style::log(
            "Selective download",
            format_args!("{} ({} range(s))", style::format_size(total_data), merged.len()),
        );

        // Plan the compact temp-file layout: [meta][range0][range1]…
        let (total_size, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        // Create the temp file in the requested directory (default: system temp).
        // create_dir_all because the output dir may not exist yet at open time.
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

        // Write metadata at the front, then stream each range into its region.
        write_all_at(named.as_file(), &meta, 0).context("temp file write failed")?;
        drop(meta);

        // Cloned handle shared across the concurrent downloaders; positional
        // writes target disjoint regions so no lock is needed.
        let write_file = Arc::new(
            named
                .as_file()
                .try_clone()
                .context("failed to clone temp file handle")?,
        );

        let client = Arc::new(client);
        let url: Arc<str> = Arc::from(url);
        let downloaded = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(tokio::sync::Semaphore::new(8));

        let mut handles = Vec::with_capacity(merged.len());
        for (i, &(data_region_off, length)) in merged.iter().enumerate() {
            let client = client.clone();
            let url = url.clone();
            let downloaded = downloaded.clone();
            let sem = sem.clone();
            let write_file = write_file.clone();
            let remote_off = payload_off + data_offset + data_region_off;
            let file_base = bases[i];

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                range_download_to_file(
                    &client,
                    &url,
                    remote_off,
                    length,
                    &write_file,
                    file_base,
                    &downloaded,
                )
                .await
            }));
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

        // Drive the bar (and the optional caller callback) from the shared byte
        // counter on a timer so progress advances as bytes stream in — even with
        // a single merged range, which otherwise sits at 0% then jumps to 100%.
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

        // Done writing; drop the writer handle and mmap the temp file read-only.
        drop(write_file);
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
        Ok(PayloadView::from_mmap_compact(mmap, remap, Box::new(named))?)
    })
}

/// Plan the compact temp-file layout for HTTP selective download.
///
/// Returns `(total_size, remap, bases)` where the file is laid out as
/// `[meta][merged[0]][merged[1]]…`: `bases[i]` is the file offset of merged
/// range `i`, and `remap` maps each operation's payload `data_offset` to its
/// `(file_position, length)` within the range that contains it. Pure function
/// of offsets/lengths — no payload data needed — so it is unit-testable.
fn plan_compact_layout(
    meta_len: u64,
    merged: &[(u64, u64)],
    op_ranges: &[(u64, u64)],
) -> (u64, HashMap<u64, (u64, u64)>, Vec<u64>) {
    let mut bases = Vec::with_capacity(merged.len());
    let mut cursor = meta_len;
    for &(_, len) in merged {
        bases.push(cursor);
        cursor += len;
    }
    let total_size = cursor;

    let mut remap: HashMap<u64, (u64, u64)> = HashMap::with_capacity(op_ranges.len());
    for &(op_off, op_len) in op_ranges {
        if remap.contains_key(&op_off) {
            continue;
        }
        for (i, &(merged_off, merged_len)) in merged.iter().enumerate() {
            if op_off >= merged_off && op_off + op_len <= merged_off + merged_len {
                remap.insert(op_off, (bases[i] + (op_off - merged_off), op_len));
                break;
            }
        }
    }

    (total_size, remap, bases)
}

/// Download a byte range and stream it straight to `file` at `file_base` via
/// positional writes — never buffering the whole range in memory. Increments
/// `downloaded` per chunk for progress. Mirrors [`range_download`]'s retry and
/// HTTP-200-fallback behavior.
async fn range_download_to_file(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    file: &std::fs::File,
    file_base: u64,
    downloaded: &AtomicU64,
) -> Result<()> {
    use futures::StreamExt;

    let end = offset + length - 1;
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
            let mut stream = resp.bytes_stream();
            let mut written = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("stream error")?;
                write_all_at(file, &chunk, file_base + written).context("temp file write failed")?;
                written += chunk.len() as u64;
                downloaded.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
            // A short range would leave zero-filled gaps in the temp file →
            // corrupt extraction. Fail loudly instead.
            if written != length {
                bail!("short read: got {written} of {length} bytes for range {offset}-{end}");
            }
            return Ok(());
        }

        if status.is_success() {
            // 200 fallback: server ignored Range and returns the whole file.
            // Skip `offset` bytes, then write exactly `length` bytes to disk.
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
                        write_all_at(file, &chunk[..take], file_base + written)
                            .context("temp file write failed")?;
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
        let client = build_client(insecure, user_agent)?;
        let (total_size, head) = fetch_total_size_and_head(&client, url).await?;
        if head.len() < 4 || &head[..4] != ZIP_MAGIC {
            bail!(
                "URL is not an OTA ZIP (magic: {:02x?})",
                &head[..4.min(head.len())]
            );
        }
        let cd = fetch_zip_cd(&client, url, total_size).await?;

        let (text_bytes, pb_bytes) = tokio::try_join!(
            download_stored_zip_entry(&client, url, &cd, ota_metadata::text_entry_name()),
            download_stored_zip_entry(&client, url, &cd, ota_metadata::pb_entry_name()),
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

/// One-shot fetch of bytes 0..=3 that returns both the file's total size (from
/// Content-Range or Content-Length) and the first four bytes for magic detection.
async fn fetch_total_size_and_head(client: &reqwest::Client, url: &str) -> Result<(u64, Vec<u8>)> {
    let resp = client
        .get(url)
        .header("Range", "bytes=0-3")
        .send()
        .await?
        .error_for_status()?;

    let total_size = if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit('/').next())
            .and_then(|s| s.parse::<u64>().ok())
            .context("cannot determine file size from Content-Range")?
    } else {
        resp.content_length()
            .context("server returned no Content-Length")?
    };

    let head = resp.bytes().await?.to_vec();
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
    let buf = range_download(client, url, entry.local_off, optimistic).await?;
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

    // LFH extra exceeded headroom — fall back to a second range request.
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

fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut merged = Vec::new();
    let (mut cs, mut cl) = ranges[0];
    const GAP: u64 = 256 * 1024;
    for &(s, l) in &ranges[1..] {
        let ce = cs + cl;
        if s <= ce + GAP {
            cl = (s + l).max(ce) - cs;
        } else {
            merged.push((cs, cl));
            cs = s;
            cl = l;
        }
    }
    merged.push((cs, cl));
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compact layout packs `[meta][range0][range1]…` and remaps each op's
    /// payload data_offset to its position within the file range that holds it.
    #[test]
    fn plan_compact_layout_maps_ops_into_ranges() {
        let meta_len = 24u64;
        let merged = [(100u64, 50u64), (200u64, 30u64)];
        // Three ops: two inside range0, one filling range1.
        let op_ranges = [(100u64, 10u64), (110u64, 40u64), (200u64, 30u64)];

        let (total, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        assert_eq!(bases, vec![24, 74]); // meta_len, meta_len + 50
        assert_eq!(total, 24 + 50 + 30);
        assert_eq!(remap[&100], (24, 10)); // start of range0
        assert_eq!(remap[&110], (34, 40)); // 10 bytes into range0
        assert_eq!(remap[&200], (74, 30)); // start of range1
    }

    /// remap positions must point at the same bytes that a contiguous on-disk
    /// layout would, for non-adjacent ops within a merged range.
    #[test]
    fn plan_compact_layout_single_range_gap() {
        let meta_len = 0u64;
        let merged = [(0u64, 100u64)];
        // ops at 0 and 60, leaving a gap [10,60) that stays on disk.
        let op_ranges = [(0u64, 10u64), (60u64, 40u64)];

        let (total, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        assert_eq!(bases, vec![0]);
        assert_eq!(total, 100);
        assert_eq!(remap[&0], (0, 10));
        assert_eq!(remap[&60], (60, 40)); // offset within the range is preserved
    }

    #[test]
    fn merge_ranges_collapses_within_gap() {
        // Two ranges closer than GAP merge into one spanning both.
        let merged = merge_ranges(&[(0, 100), (100 + 1024, 50)]);
        assert_eq!(merged, vec![(0, 100 + 1024 + 50)]);
        // A range farther than GAP stays separate.
        let merged = merge_ranges(&[(0, 100), (100 + 512 * 1024, 50)]);
        assert_eq!(merged, vec![(0, 100), (100 + 512 * 1024, 50)]);
    }
}
