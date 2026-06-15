/// Compute and write back dm-verity hash tree and FEC data into extracted partition images.
///
/// Functionality:
/// 1. Compute the dm-verity Merkle hash tree from data blocks and write it back
/// 2. Compute Reed-Solomon FEC parity data and write it back
///
/// Both are needed to produce partition images that pass Android's verified boot checks.
use std::path::Path;

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::extract::fec::{self, FEC_RSM, RsEncoder};
use crate::proto::PartitionUpdate;
use crate::style;

const SHA256_DIGEST_SIZE: usize = 32;

/// Align `value` up to the next multiple of `alignment`.
#[inline]
fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// Positional read (pread / seek_read). Returns the number of bytes read.
#[inline]
fn pread(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
}

/// Fill `buf` completely starting at `offset`, looping over short reads.
fn pread_exact(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let n = pread(file, &mut buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        done += n;
    }
    Ok(())
}

/// Zero `buf`, then read up to `buf.len()` bytes at `offset` clamped to `file_len`
/// (bytes past EOF stay zero). Returns the count of real bytes read.
fn read_clamped(
    file: &std::fs::File,
    buf: &mut [u8],
    offset: u64,
    file_len: u64,
) -> Result<usize> {
    buf.fill(0);
    if offset >= file_len {
        return Ok(0);
    }
    let want = (buf.len() as u64).min(file_len - offset) as usize;
    pread_exact(file, &mut buf[..want], offset)?;
    Ok(want)
}

/// Compute the dm-verity hash tree and write it into the partition image.
///
/// Returns `Ok(true)` if hash tree was computed and written, `Ok(false)` if partition
/// has no hash tree metadata, or `Err` on failure.
pub fn compute_and_write_hash_tree(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    let hash_tree_data_extent = match &partition.hash_tree_data_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };
    let hash_tree_extent = match &partition.hash_tree_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };

    let salt = partition.hash_tree_salt.as_deref().unwrap_or(&[]);
    let algorithm = partition.hash_tree_algorithm.as_deref().unwrap_or("sha256");
    if algorithm != "sha256" {
        bail!("unsupported hash tree algorithm: '{algorithm}'");
    }

    if block_size == 0 {
        bail!("invalid block size: 0");
    }
    let bs = block_size as u64;
    let data_extent_offset = hash_tree_data_extent.start_block.unwrap_or(0) * bs;
    let data_extent_size = hash_tree_data_extent.num_blocks.unwrap_or(0) * bs;
    let hash_tree_offset = hash_tree_extent.start_block.unwrap_or(0) * bs;

    if data_extent_size == 0 {
        return Ok(false);
    }

    // A single read+write handle. Every read (pread) and write (pwrite) uses an
    // explicit offset, so the computation never holds more than a small bounded
    // buffer regardless of partition size — the leaf level is streamed to disk
    // and the (tiny) intermediate levels are read back from disk on demand.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(output_path)
        .with_context(|| format!("failed to open '{}' for hash tree", output_path.display()))?;
    let file_len = file.metadata()?.len();

    // --- Level layout (pure arithmetic, no data needed) ---
    // Leaf level: one hash per data block, padded up to a block boundary.
    let leaf_block_count = data_extent_size / bs;
    let leaf_size = align_up(leaf_block_count * SHA256_DIGEST_SIZE as u64, bs);

    // Intermediate levels (build order, nearest-leaf first) until size == bs (root).
    let mut inter_sizes: Vec<u64> = Vec::new();
    let mut prev_size = leaf_size;
    while prev_size > bs {
        let bc = prev_size / bs;
        inter_sizes.push(align_up(bc * SHA256_DIGEST_SIZE as u64, bs));
        prev_size = *inter_sizes.last().unwrap();
    }

    // Write-back order matches the reference: intermediate levels deepest-first,
    // then the leaf level last. Resolve each level's absolute file offset.
    let inter_total: u64 = inter_sizes.iter().sum();
    let leaf_offset = hash_tree_offset + inter_total;
    let inter_offsets: Vec<u64> = {
        let mut offs = vec![0u64; inter_sizes.len()];
        let mut acc = hash_tree_offset;
        for i in (0..inter_sizes.len()).rev() {
            offs[i] = acc;
            acc += inter_sizes[i];
        }
        offs
    };

    // --- Stream the leaf level straight to disk (bounded per-thread buffers) ---
    // The leaf is the only partition-proportional level; everything above is <1%.
    const GROUP_SLOTS: u64 = 8192; // 8192 hashes -> 256 KiB pwrite per group
    let total_slots = leaf_size / SHA256_DIGEST_SIZE as u64;
    let group_count = total_slots.div_ceil(GROUP_SLOTS);

    (0..group_count)
        .into_par_iter()
        .try_for_each(|g| -> Result<()> {
            let slot_start = g * GROUP_SLOTS;
            let slot_end = (slot_start + GROUP_SLOTS).min(total_slots);
            let mut out = vec![0u8; ((slot_end - slot_start) as usize) * SHA256_DIGEST_SIZE];
            let mut block = vec![0u8; bs as usize];

            for slot in slot_start..slot_end {
                // Slots >= leaf_block_count are zero padding (already zero in `out`).
                if slot < leaf_block_count {
                    let n = read_clamped(&file, &mut block, data_extent_offset + slot * bs, file_len)?;
                    let mut hasher = Sha256::new();
                    hasher.update(salt);
                    hasher.update(&block[..n]);
                    let dst = ((slot - slot_start) as usize) * SHA256_DIGEST_SIZE;
                    out[dst..dst + SHA256_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
                }
            }
            write_at_offset(&file, &out, leaf_offset + slot_start * SHA256_DIGEST_SIZE as u64)?;
            Ok(())
        })?;

    // --- Intermediate levels: small, computed serially and written to disk ---
    // Level 0 reads the just-written leaf from disk; higher levels read the
    // previous (small) level kept in memory. `scratch` materializes the previous
    // block from either source so the hashing logic is identical to the reference.
    let salt_len = salt.len();
    let mut prev_mem: Option<Vec<u8>> = None;
    for (i, &level_size) in inter_sizes.iter().enumerate() {
        let prev_len = prev_mem.as_ref().map(|b| b.len() as u64).unwrap_or(leaf_size);
        let level_block_count = prev_len / bs;
        let mut level = vec![0u8; level_size as usize];
        let mut salt_buf = vec![0u8; salt_len + bs as usize];
        salt_buf[..salt_len].copy_from_slice(salt);
        let mut scratch = vec![0u8; bs as usize];

        for b in 0..level_block_count {
            let pblen = match &prev_mem {
                Some(buf) => {
                    let s = (b * bs) as usize;
                    let e = (s + bs as usize).min(buf.len());
                    scratch[..e - s].copy_from_slice(&buf[s..e]);
                    e - s
                }
                None => read_clamped(&file, &mut scratch, leaf_offset + b * bs, file_len)?,
            };
            salt_buf[salt_len..salt_len + pblen].copy_from_slice(&scratch[..pblen]);
            for x in &mut salt_buf[salt_len + pblen..salt_len + bs as usize] {
                *x = 0;
            }
            let h = Sha256::digest(&salt_buf[..salt_len + bs as usize]);
            let dst = (b * SHA256_DIGEST_SIZE as u64) as usize;
            level[dst..dst + SHA256_DIGEST_SIZE].copy_from_slice(&h);
        }

        write_at_offset(&file, &level, inter_offsets[i])?;
        prev_mem = Some(level);
    }

    Ok(true)
}

/// Compute FEC (Forward Error Correction) parity data and write it into the partition image.
///
/// Returns `Ok(true)` if FEC was computed and written, `Ok(false)` if partition
/// has no FEC metadata, or `Err` on failure.
pub fn compute_and_write_fec(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    let fec_data_extent = match &partition.fec_data_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };
    let fec_extent = match &partition.fec_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };

    if block_size == 0 {
        bail!("invalid block size: 0");
    }
    let bs = block_size as u64;
    let fec_roots = partition.fec_roots.unwrap_or(2);
    // Validate before constructing the RS encoder so untrusted metadata can never
    // trip an assertion (which, under panic=abort, would abort the whole process).
    if fec_roots == 0 || fec_roots >= FEC_RSM {
        bail!("invalid fec_roots: {fec_roots} (must be in 1..{FEC_RSM})");
    }
    let fec_rsn = FEC_RSM - fec_roots;

    let fec_data_extent_offset = fec_data_extent.start_block.unwrap_or(0) * bs;
    let fec_data_extent_size = fec_data_extent.num_blocks.unwrap_or(0) * bs;
    let fec_write_offset = fec_extent.start_block.unwrap_or(0) * bs;
    let fec_extent_size = fec_extent.num_blocks.unwrap_or(0) * bs;
    let fec_data_size = fec::fec_ecc_get_data_size(fec_data_extent_size, fec_roots);

    // Validate that the proto-declared FEC extent size matches the computed size
    if fec_extent_size != fec_data_size {
        bail!(
            "FEC extent size mismatch: proto declares {} but computed {}",
            fec_extent_size,
            fec_data_size
        );
    }
    if fec_data_extent_size == 0 {
        return Ok(false);
    }

    let rounds = (fec_data_extent_size / bs).div_ceil(fec_rsn as u64);

    // Single read+write handle; reads/writes use explicit offsets (pread/pwrite).
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(output_path)
        .with_context(|| format!("failed to open '{}' for FEC", output_path.display()))?;
    let file_len = file.metadata()?.len();

    let chunk_size = block_size as usize * fec_roots as usize;

    // Each round produces an independent, contiguous `chunk_size` slice of parity
    // and is written straight to disk — no partition-proportional accumulator.
    (0..rounds).into_par_iter().try_for_each(|round_idx| -> Result<()> {
        let rs = RsEncoder::try_new(fec_roots as usize).map_err(|e| anyhow::anyhow!(e))?;
        let mut block = vec![0u8; block_size as usize];
        let rs_block_size = block_size as usize * fec_rsn as usize;
        let mut rs_blocks = vec![0u8; rs_block_size];
        let mut parity = vec![0u8; chunk_size];

        // Construct RS blocks from interleaved data
        for j in 0..fec_rsn as usize {
            let offset = fec::fec_ecc_interleave(
                round_idx * fec_rsn as u64 * bs + j as u64,
                fec_rsn,
                rounds,
            );

            if offset < fec_data_extent_size {
                read_clamped(&file, &mut block, fec_data_extent_offset + offset, file_len)?;
            } else {
                block.fill(0);
            }

            // Place into RS block: rsBlocks[col * rsn + row] = block[col]
            for k in 0..block_size as usize {
                rs_blocks[k * fec_rsn as usize + j] = block[k];
            }
        }

        // Encode each byte column
        for j in 0..block_size as usize {
            let data_start = j * fec_rsn as usize;
            let data_slice = &rs_blocks[data_start..data_start + fec_rsn as usize];
            let parity_start = j * fec_roots as usize;
            let parity_end = parity_start + fec_roots as usize;
            rs.encode(data_slice, &mut parity[parity_start..parity_end]);
        }

        write_at_offset(&file, &parity, fec_write_offset + round_idx * chunk_size as u64)?;
        Ok(())
    })?;

    Ok(true)
}

/// Run verify-update (hash tree + FEC write-back) for selected partitions.
pub fn verify_update_partitions(
    partitions: &[&PartitionUpdate],
    output_dir: &Path,
    block_size: u32,
    threads: usize,
    quiet: bool,
) -> Result<()> {
    if block_size == 0 || block_size > 16 * 1024 * 1024 {
        bail!("invalid block size: {block_size}");
    }

    let thread_count = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .context("failed to create thread pool")?;

    pool.install(|| {
        partitions
            .par_iter()
            .try_for_each(|partition| -> Result<()> {
                let name = &partition.partition_name;
                let output_path = output_dir.join(format!("{name}.img"));

                if !output_path.exists() {
                    if !quiet {
                        style::elog_skip(name, "file not found");
                    }
                    return Ok(());
                }

                // Hash tree
                let ht_result = compute_and_write_hash_tree(partition, &output_path, block_size)?;
                if ht_result && !quiet {
                    style::elog_ok("HASH", name);
                }

                // FEC (only if hash tree succeeded)
                if ht_result {
                    let fec_result = compute_and_write_fec(partition, &output_path, block_size)?;
                    if fec_result && !quiet {
                        style::elog_ok("FEC", name);
                    }
                }

                Ok(())
            })
    })
}

/// Write data at a specific byte offset in a file (platform-specific positional write).
fn write_at_offset(file: &std::fs::File, data: &[u8], offset: u64) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(data, offset)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0;
        while written < data.len() {
            let n = file.seek_write(&data[written..], offset + written as u64)?;
            written += n;
        }
    }
    Ok(())
}
