pub mod bufpool;
pub mod decompress;
pub mod fec;
pub mod lz4diff;
pub mod operation;
pub mod verify;
pub mod verify_update;
pub mod writer;

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;

use crate::payload::PayloadView;
use crate::storage::ReadOnlyFile;
use crate::style;

use operation::{OpType, OperationTask};
use writer::PartitionWriter;

/// Size of the per-thread streaming-decompression scratch buffer. Large enough
/// that a typical (~2 MiB) operation is written in a single pwrite, while keeping
/// peak memory bounded and independent of the decompressed output size.
const DECODE_CHUNK_SIZE: usize = 4 << 20; // 4 MiB

thread_local! {
    /// Reused decode buffer, kept allocated at `DECODE_CHUNK_SIZE` across operations
    /// so the hot path neither reallocates nor re-zeroes per operation.
    static DECODE_CHUNK: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Configuration for extraction.
pub struct ExtractConfig {
    pub verify_ops: bool,
    pub threads: usize,
    pub quiet: bool,
    /// Source directory for delta/incremental OTA (contains old partition .img files)
    pub source_dir: Option<String>,
    /// Custom output paths per partition (from --out-config)
    pub out_config: Option<HashMap<String, PathBuf>>,
    /// Reports `(completed_ops, total_ops)` even in quiet mode.
    /// Native workers may invoke callbacks concurrently.
    pub progress: Option<crate::input::ProgressCallback>,
}

/// Extract selected partitions from a payload.
pub fn extract_partitions(
    payload: &PayloadView,
    output_dir: &Path,
    partition_names: &[String],
    config: &ExtractConfig,
) -> Result<()> {
    let partitions = payload.selected_partitions(partition_names);
    if partitions.is_empty() {
        bail!("no partitions selected for extraction");
    }

    let block_size = payload.block_size();
    if block_size == 0 || block_size > 16 * 1024 * 1024 {
        bail!("invalid block size: {block_size}");
    }
    std::fs::create_dir_all(output_dir)?;

    // Check if any partition has delta operations
    let has_delta_ops = partitions.iter().any(|p| {
        p.operations.iter().any(|op| {
            let op_type = op.r#type();
            matches!(
                op_type,
                crate::proto::install_operation::Type::SourceCopy
                    | crate::proto::install_operation::Type::SourceBsdiff
                    | crate::proto::install_operation::Type::BrotliBsdiff
                    | crate::proto::install_operation::Type::Puffdiff
                    | crate::proto::install_operation::Type::Zucchini
                    | crate::proto::install_operation::Type::Lz4diffBsdiff
                    | crate::proto::install_operation::Type::Lz4diffPuffdiff
            )
        })
    });

    if has_delta_ops && config.source_dir.is_none() {
        bail!(
            "this is a delta/incremental OTA payload — \
             source partition directory is required (use --source-dir)"
        );
    }

    let multi_progress = MultiProgress::new();
    let progress_style =
        ProgressStyle::with_template("{prefix:>20} {msg:>10} [{bar:40.cyan/blue}] {percent:>3}%")
            .unwrap()
            .progress_chars("=> ");

    let extract_partition = |partition: &&crate::proto::PartitionUpdate| -> Result<()> {
                let part_name = &partition.partition_name;
                let output_path = if let Some(ref out_config) = config.out_config {
                    if let Some(custom_path) = out_config.get(part_name) {
                        // Ensure parent directory exists for custom paths
                        if let Some(parent) = custom_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        custom_path.clone()
                    } else {
                        output_dir.join(format!("{part_name}.img"))
                    }
                } else {
                    output_dir.join(format!("{part_name}.img"))
                };

                // Determine partition size
                let part_size = if let Some(size) = partition
                    .new_partition_info
                    .as_ref()
                    .and_then(|info| info.size)
                {
                    size
                } else {
                    partition.operations.iter().try_fold(0, |size, op| {
                        op.dst_extents.iter().try_fold(size, |size, extent| {
                            let start = extent.start_block.unwrap_or(0);
                            if start == u64::MAX {
                                return Ok::<u64, anyhow::Error>(size);
                            }
                            let end = start.checked_add(extent.num_blocks.unwrap_or(0))
                                .and_then(|end| end.checked_mul(block_size as u64))
                                .context("destination extent size overflow")?;
                            Ok(size.max(end))
                        })
                    })?
                };

                // Create pre-allocated output file
                let writer = PartitionWriter::new(&output_path, part_size, block_size)?;

                // Open source partition for delta OTA if needed
                let source_file = if let Some(source_dir) = &config.source_dir {
                    let src_path = Path::new(source_dir).join(format!("{part_name}.img"));
                    if std::fs::exists(&src_path)? {
                        Some(ReadOnlyFile::open(&src_path)?)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Build operation tasks
                let mut tasks: Vec<OperationTask> = Vec::with_capacity(partition.operations.len());
                for op in &partition.operations {
                    let op_type_raw = op.r#type();
                    let op_type = OpType::from_proto(op_type_raw).map_err(|_| {
                        crate::error::PayloadError::UnsupportedOperation(op_type_raw as i32)
                    })?;

                    let src_extents: Vec<(u64, u64)> = op
                        .src_extents
                        .iter()
                        .map(|e| (e.start_block.unwrap_or(0), e.num_blocks.unwrap_or(0)))
                        .collect();

                    let dst_extents: Vec<(u64, u64)> = op
                        .dst_extents
                        .iter()
                        .map(|e| (e.start_block.unwrap_or(0), e.num_blocks.unwrap_or(0)))
                        .collect();

                    tasks.push(OperationTask {
                        op_type,
                        data_offset: op.data_offset.unwrap_or(0),
                        data_length: op.data_length.unwrap_or(0),
                        src_extents,
                        dst_extents,
                        data_sha256: op.data_sha256_hash.clone(),
                    });
                }

                // Sort by data_offset for sequential payload reads
                tasks.sort_by_key(|t| t.data_offset);

                // Setup progress bar
                let pb = if !config.quiet {
                    let pb = multi_progress.add(ProgressBar::new(tasks.len() as u64));
                    pb.set_style(progress_style.clone());
                    pb.set_prefix(style::bold().apply_to(part_name).to_string());
                    pb.set_message(style::format_size(part_size));
                    Some(pb)
                } else {
                    None
                };

                let completed = AtomicU64::new(0);
                let total_ops = tasks.len() as u64;

                let process_task = |task: &OperationTask| -> Result<()> {
                    process_operation(
                        payload,
                        task,
                        &writer,
                        block_size,
                        config,
                        source_file.as_ref(),
                    )?;

                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(pb) = &pb {
                        pb.set_position(done);
                    }
                    // Report progress regardless of `quiet` — headless callers
                    // (GUI) set quiet=true but still consume the callback.
                    if let Some(cb) = &config.progress {
                        cb(done, total_ops);
                    }

                    Ok(())
                };
                tasks.par_iter().try_for_each(process_task)?;

                if let Some(pb) = &pb {
                    pb.finish();
                }

                Ok(())
    };

    let thread_count = if config.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        config.threads
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .context("failed to create thread pool")?;
    pool.install(|| partitions.par_iter().try_for_each(extract_partition))
}

/// Process a single extraction operation.
fn process_operation(
    payload: &PayloadView,
    task: &OperationTask,
    writer: &PartitionWriter,
    block_size: u32,
    config: &ExtractConfig,
    source_data: Option<&ReadOnlyFile>,
) -> Result<()> {
    match task.op_type {
        OpType::Zero | OpType::Discard => {
            // The output file is created via set_len() which guarantees zero-filled
            // content on all major platforms (Linux ext4/btrfs, Windows NTFS, macOS APFS).
            // Skipping explicit zero writes avoids redundant I/O.
        }
        OpType::Replace | OpType::ReplaceBz | OpType::ReplaceXz | OpType::ReplaceZstd => {
            if task.op_type == OpType::Replace {
                let blob = get_blob(payload, task)?;
                if config.verify_ops {
                    verify::verify_sha256(blob, &task.data_sha256)?;
                }
                return write_to_extents(blob, &task.dst_extents, writer, block_size);
            }
            if config.verify_ops {
                verify_blob(payload, task)?;
            }
            let input = payload.blob_reader_raw(task.data_offset, task.data_length)?;
            let mut reader = decompress::decoder_for(task.op_type, input)?;
            let mut sink = ExtentWriter::new(writer, block_size, &task.dst_extents);
            stream_to_extents(&mut reader, &mut sink)?;
        }
        OpType::SourceCopy => {
            let src = source_data
                .ok_or_else(|| anyhow::anyhow!("SOURCE_COPY requires source partition data"))?;
            copy_source_extents(src, &task.src_extents, &task.dst_extents, writer, block_size)?;
        }
        OpType::SourceBsdiff | OpType::BrotliBsdiff => {
            // BSDIFF40 (bz2) / BSDF2 (brotli) are both magic-prefixed bsdiff
            // patches; patch_bsdf2 auto-detects the format and compression.
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("{:?} requires source partition data", task.op_type)
            })?;
            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }
            bufpool::with_extent_buffer(
                0,
                |buf| {
                    read_from_extents(src, &task.src_extents, block_size, buf)?;
                    let mut patched = Vec::new();
                    bsdiff_android::patch_bsdf2(buf, blob, &mut patched)
                        .map_err(|e| anyhow::anyhow!("{:?} patch failed: {e}", task.op_type))?;
                    write_to_extents(&patched, &task.dst_extents, writer, block_size)
                },
            )?;
        }
        OpType::Puffdiff => {
            bail!(
                "PUFFDIFF operations are not yet supported — \
                 puffdiff uses the PUF1 patch format (puffin library), \
                 which is not compatible with bsdiff"
            );
        }
        OpType::Zucchini => {
            bail!(
                "ZUCCHINI operations are not yet supported — \
                 zucchini uses Chromium's custom binary diff format, \
                 which is not compatible with bsdiff"
            );
        }
        OpType::Lz4diffBsdiff | OpType::Lz4diffPuffdiff => {
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("{:?} requires source partition data", task.op_type)
            })?;
            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }
            bufpool::with_extent_buffer(
                0,
                |buf| {
                    read_from_extents(src, &task.src_extents, block_size, buf)?;
                    let patched = lz4diff::apply_lz4diff(buf, blob, task.op_type)?;
                    write_to_extents(&patched, &task.dst_extents, writer, block_size)
                },
            )?;
        }
    }

    Ok(())
}

/// Borrow operation bytes directly from the payload mapping.
#[inline]
fn get_blob<'a>(payload: &'a PayloadView, task: &OperationTask) -> Result<&'a [u8]> {
    Ok(payload.blob_slice_raw(task.data_offset, task.data_length)?)
}

/// Verify operation input directly from the payload mapping.
fn verify_blob(payload: &PayloadView, task: &OperationTask) -> Result<()> {
    if task.data_sha256.is_none() {
        return Ok(());
    }
    Ok(verify::verify_sha256(get_blob(payload, task)?, &task.data_sha256)?)
}

fn stream_to_extents(reader: &mut impl Read, sink: &mut ExtentWriter<'_>) -> Result<()> {
    DECODE_CHUNK.with(|cell| -> Result<()> {
        let mut buffer = cell.borrow_mut();
        buffer.resize(DECODE_CHUNK_SIZE, 0);
        loop {
            let mut filled = 0;
            while filled < buffer.len() {
                match reader.read(&mut buffer[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("operation stream read failed"),
                }
            }
            if filled == 0 {
                break;
            }
            sink.write(&buffer[..filled])?;
        }
        Ok(())
    })
}

fn extents_byte_size(extents: &[(u64, u64)], block_size: u32) -> Result<usize> {
    let size = extents.iter().try_fold(0u64, |total, &(_, blocks)| {
        blocks.checked_mul(block_size as u64)
            .and_then(|length| total.checked_add(length))
            .context("source extent size overflow")
    })?;
    usize::try_from(size).context("source extents exceed address space")
}

/// Sparse source extents represent zero bytes, not a file offset. Non-sparse
/// extents must be present in full; silently truncating would corrupt patches.
fn read_from_extents(
    source: &ReadOnlyFile,
    extents: &[(u64, u64)],
    block_size: u32,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    let size = extents_byte_size(extents, block_size)?;
    buffer.clear();
    buffer.try_reserve(size).context("source extent allocation failed")?;
    buffer.resize(size, 0);
    let mut position = 0;
    for &(start, blocks) in extents {
        let length = blocks.checked_mul(block_size as u64)
            .and_then(|length| usize::try_from(length).ok())
            .context("source extent size overflow")?;
        if start != u64::MAX {
            let offset = start.checked_mul(block_size as u64)
                .context("source extent offset overflow")?;
            source.read_exact_at(&mut buffer[position..position + length], offset)
                .context("source extent is truncated or unreadable")?;
        }
        position += length;
    }
    Ok(())
}

/// SOURCE_COPY uses constant scratch space even for partition-sized extents.
fn copy_source_extents(
    source: &ReadOnlyFile,
    extents: &[(u64, u64)],
    destinations: &[(u64, u64)],
    writer: &PartitionWriter,
    block_size: u32,
) -> Result<()> {
    let mut sink = ExtentWriter::new(writer, block_size, destinations);
    DECODE_CHUNK.with(|cell| -> Result<()> {
        let mut buffer = cell.borrow_mut();
        for &(start, blocks) in extents {
            let length = blocks.checked_mul(block_size as u64)
                .context("source extent size overflow")?;
            let offset = if start == u64::MAX { 0 } else {
                let offset = start.checked_mul(block_size as u64)
                    .context("source extent offset overflow")?;
                if offset.checked_add(length).is_none_or(|end| end > source.len()) {
                    bail!("source extent is truncated");
                }
                offset
            };
            let mut position = 0u64;
            while position < length {
                let count = (length - position).min(DECODE_CHUNK_SIZE as u64) as usize;
                if start == u64::MAX {
                    buffer.resize(count, 0);
                    buffer.fill(0);
                    sink.write(&buffer)?;
                } else {
                    sink.write(source.read_range(offset + position, count)?)?;
                }
                position += count as u64;
            }
        }
        Ok(())
    })
}

/// Write decompressed data to non-contiguous destination extents.
fn write_to_extents(
    data: &[u8],
    extents: &[(u64, u64)],
    writer: &PartitionWriter,
    block_size: u32,
) -> Result<()> {
    ExtentWriter::new(writer, block_size, extents).write(data)
}

/// Sequentially writes a streamed byte sequence across a partition's destination
/// extents, mapping the running output position to (extent, in-extent offset).
///
/// Equivalent to feeding the full decompressed buffer to [`write_to_extents`], but
/// fed incrementally so the caller never materializes the whole output in memory.
/// Bytes beyond the total extent capacity are dropped — matching `write_to_extents`,
/// which clamps each extent write to `data.len()`.
struct ExtentWriter<'a> {
    writer: &'a PartitionWriter,
    block_size: u64,
    extents: &'a [(u64, u64)],
    idx: usize,
    pos_in_extent: u64,
}

impl<'a> ExtentWriter<'a> {
    fn new(writer: &'a PartitionWriter, block_size: u32, extents: &'a [(u64, u64)]) -> Self {
        Self {
            writer,
            block_size: block_size as u64,
            extents,
            idx: 0,
            pos_in_extent: 0,
        }
    }

    fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            if self.idx >= self.extents.len() {
                break; // output exceeds extent capacity; drop the remainder
            }
            let (start_block, num_blocks) = self.extents[self.idx];
            let capacity = num_blocks.checked_mul(self.block_size)
                .context("destination extent size overflow")?;
            if self.pos_in_extent >= capacity {
                self.idx += 1;
                self.pos_in_extent = 0;
                continue;
            }
            let remaining = capacity - self.pos_in_extent;
            let n = (data.len() as u64).min(remaining) as usize;
            if start_block != u64::MAX {
                let offset = start_block.checked_mul(self.block_size)
                    .and_then(|offset| offset.checked_add(self.pos_in_extent))
                    .context("destination extent offset overflow")?;
                self.writer.write_at(&data[..n], offset)?;
            }
            self.pos_in_extent += n as u64;
            data = &data[n..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn source_extents_preserve_holes_and_reject_truncation() {
        let path = crate::storage::test_dir().join("pe_sparse_extent_source.img");
        std::fs::write(&path, b"abcdefghijkl").unwrap();
        let source = ReadOnlyFile::open(&path).unwrap();
        let mut buffer = Vec::new();
        read_from_extents(&source, &[(1, 1), (u64::MAX, 2), (0, 1)], 4, &mut buffer).unwrap();
        assert_eq!(buffer, b"efgh\0\0\0\0\0\0\0\0abcd");
        assert!(read_from_extents(&source, &[(2, 2)], 4, &mut buffer).is_err());
        assert!(read_from_extents(&source, &[(u64::MAX - 1, 1)], 4, &mut buffer).is_err());
        assert!(extents_byte_size(&[(0, u64::MAX)], 4).is_err());
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn source_copy_streams_across_sparse_extents() {
        let source_path = crate::storage::test_dir().join("pe_stream_source.img");
        let output_path = crate::storage::test_dir().join("pe_stream_destination.img");
        let bytes = vec![0x5a; DECODE_CHUNK_SIZE + 7];
        std::fs::write(&source_path, &bytes).unwrap();
        let source = ReadOnlyFile::open(&source_path).unwrap();
        let writer = PartitionWriter::new(&output_path, bytes.len() as u64 + 3, 1).unwrap();
        copy_source_extents(
            &source, &[(0, bytes.len() as u64), (u64::MAX, 3)],
            &[(0, 5), (5, bytes.len() as u64 - 2)], &writer, 1,
        ).unwrap();
        drop(writer);
        let actual = std::fs::read(&output_path).unwrap();
        assert_eq!(&actual[..bytes.len()], &bytes);
        assert_eq!(&actual[bytes.len()..], &[0, 0, 0]);
        let writer = PartitionWriter::new(&output_path, 4, 1).unwrap();
        assert!(copy_source_extents(&source, &[(bytes.len() as u64, 1)], &[(0, 1)], &writer, 1).is_err());
        drop(writer);
        drop(source);
        std::fs::remove_file(source_path).unwrap();
        std::fs::remove_file(output_path).unwrap();
    }

    /// Streaming across extents in awkward chunk sizes must produce byte-identical
    /// output to the original whole-buffer `write_to_extents`.
    #[test]
    fn extent_writer_equiv() {
        let bs = 4096u32;
        let extents = vec![(2u64, 3u64), (10, 1), (20, 2)]; // non-contiguous
        let total = (3 + 1 + 2) * bs as usize;
        let data: Vec<u8> = (0..total).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8).collect();

        let dir = crate::storage::test_dir();
        let pa = dir.join("pe_ew_a.img");
        let pb = dir.join("pe_ew_b.img");
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
        let cap = 24 * bs as u64;

        let wa = PartitionWriter::new(&pa, cap, bs).unwrap();
        write_to_extents(&data, &extents, &wa, bs).unwrap();
        drop(wa);

        let wb = PartitionWriter::new(&pb, cap, bs).unwrap();
        {
            let mut ew = ExtentWriter::new(&wb, bs, &extents);
            let mut off = 0;
            for &chunk in [1usize, 4095, 1, 8192, 100000, 33].iter().cycle() {
                if off >= data.len() {
                    break;
                }
                let end = (off + chunk).min(data.len());
                ew.write(&data[off..end]).unwrap();
                off = end;
            }
        }
        drop(wb);

        assert_eq!(std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    /// The streaming decoder must reproduce the original bytes for every codec,
    /// even when read in tiny chunks (covers zstd, which the test package lacks).
    #[test]
    fn decoder_for_streams_all_codecs() {
        let data: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();

        let z = zstd::stream::encode_all(&data[..], 3).unwrap();
        let mut x = Vec::new();
        xz2::read::XzEncoder::new(&data[..], 6)
            .read_to_end(&mut x)
            .unwrap();
        let mut b = Vec::new();
        bzip2::read::BzEncoder::new(&data[..], bzip2::Compression::new(6))
            .read_to_end(&mut b)
            .unwrap();

        for (ot, comp) in [
            (OpType::ReplaceZstd, &z),
            (OpType::ReplaceXz, &x),
            (OpType::ReplaceBz, &b),
        ] {
            let mut reader = decompress::decoder_for(ot, comp.as_slice()).unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 7]; // tiny chunks stress the streaming loop
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            assert_eq!(out, data, "codec {ot:?} roundtrip mismatch");
        }
    }
}
