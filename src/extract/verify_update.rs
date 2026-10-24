/// Bounded dm-verity hash-tree and Reed-Solomon FEC generation.
///
/// Levels are stored root-first, with the leaf level last. Only a hash block or
/// one FEC round is buffered; independent work is parallelized using positional
/// file I/O.
use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::extract::fec::{FEC_BLOCKSIZE, FEC_RSM, RsEncoder};
use crate::proto::{Extent, PartitionUpdate};
use crate::storage::{read_exact_at, write_all_at};
use crate::style;

pub(super) const SHA256_DIGEST_SIZE: usize = 32;

pub(super) fn extent_range(extent: &Extent, block_size: u32) -> Result<Range<u64>> {
    let bs = u64::from(block_size);
    let start = extent.start_block.unwrap_or(0).checked_mul(bs)
        .context("extent offset overflow")?;
    let size = extent.num_blocks.unwrap_or(0).checked_mul(bs)
        .context("extent size overflow")?;
    Ok(start..start.checked_add(size).context("extent end overflow")?)
}

#[derive(Debug)]
pub(super) struct TreeLevel {
    pub input_offset: u64,
    pub input_blocks: u64,
    pub output_offset: u64,
    pub output_size: u64,
}

/// Resolve the on-disk tree layout in build order (leaf first), without holding
/// any hashes. Each level contains salted hashes of full input blocks followed
/// by zero padding to the next block boundary.
pub(super) fn tree_layout(
    partition: &PartitionUpdate,
    block_size: u32,
    file_len: u64,
) -> Result<Option<Vec<TreeLevel>>> {
    let (data_extent, tree_extent) = match (
        &partition.hash_tree_data_extent, &partition.hash_tree_extent,
    ) {
        (None, None) => return Ok(None),
        (Some(data), Some(tree)) => (data, tree),
        _ => bail!("incomplete hash tree extents"),
    };
    let algorithm = partition.hash_tree_algorithm.as_deref().unwrap_or("sha256");
    if algorithm != "sha256" {
        bail!("unsupported hash tree algorithm: '{algorithm}'");
    }
    // At least two hashes must fit, otherwise the tree cannot converge.
    if block_size < 64 || !block_size.is_power_of_two() || block_size > 16 * 1024 * 1024 {
        bail!("invalid hash tree block size: {block_size}");
    }
    let bs = u64::from(block_size);
    let data = extent_range(data_extent, block_size)?;
    let tree = extent_range(tree_extent, block_size)?;
    if data.end > file_len || tree.end > file_len {
        bail!("hash tree extents exceed partition size");
    }
    if data.is_empty() {
        if !tree.is_empty() {
            bail!("nonempty hash tree for empty data extent");
        }
        return Ok(None);
    }
    if data.start < tree.end && tree.start < data.end {
        bail!("hash tree overlaps its data extent");
    }

    let mut sizes = Vec::new();
    let mut blocks = (data.end - data.start) / bs;
    loop {
        let hashes = blocks.checked_mul(SHA256_DIGEST_SIZE as u64)
            .context("hash tree size overflow")?;
        let size = hashes.div_ceil(bs).checked_mul(bs).context("hash tree size overflow")?;
        sizes.push(size);
        if size == bs {
            break;
        }
        blocks = size / bs;
    }
    let total = sizes.iter().try_fold(0u64, |sum, size| sum.checked_add(*size))
        .context("hash tree size overflow")?;
    if total != tree.end - tree.start {
        bail!("hash tree extent size mismatch: declared {}, computed {total}", tree.end - tree.start);
    }
    let mut levels = Vec::with_capacity(sizes.len());
    let mut input_offset = data.start;
    let mut input_blocks = (data.end - data.start) / bs;
    let mut output_end = tree.end;
    for size in sizes {
        let output_offset = output_end - size;
        levels.push(TreeLevel { input_offset, input_blocks, output_offset, output_size: size });
        input_offset = output_offset;
        input_blocks = size / bs;
        output_end = output_offset;
    }
    Ok(Some(levels))
}

/// Fill one output hash block, including zero padding, from its input blocks.
pub(super) fn hash_tree_block(
    level: &TreeLevel,
    output_block: u64,
    block_size: usize,
    salt: &[u8],
    scratch: &mut [u8],
    output: &mut [u8],
    mut read: impl FnMut(&mut [u8], u64) -> std::io::Result<()>,
) -> Result<()> {
    output.fill(0);
    let hashes_per_block = block_size / SHA256_DIGEST_SIZE;
    let first = output_block * hashes_per_block as u64;
    let count = level.input_blocks.saturating_sub(first).min(hashes_per_block as u64);
    for slot in 0..count {
        read(scratch, level.input_offset + (first + slot) * block_size as u64)?;
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(&*scratch);
        let dst = slot as usize * SHA256_DIGEST_SIZE;
        output[dst..dst + SHA256_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
    }
    Ok(())
}

/// Generate all levels with bounded scratch space, then write each hash block
/// directly into its manifest-declared location.
pub fn compute_and_write_hash_tree(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    if partition.hash_tree_data_extent.is_none() && partition.hash_tree_extent.is_none() {
        return Ok(false);
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).open(output_path)
        .with_context(|| format!("failed to open '{}' for hash tree", output_path.display()))?;
    let Some(levels) = tree_layout(partition, block_size, file.metadata()?.len())? else {
        return Ok(false);
    };
    let bs = block_size as usize;
    let salt = partition.hash_tree_salt.as_deref().unwrap_or(&[]);
    for level in &levels {
        let blocks = level.output_size / u64::from(block_size);
        let write_block = |buffers: &mut (Vec<u8>, Vec<u8>), block: u64| -> Result<()> {
            hash_tree_block(level, block, bs, salt, &mut buffers.0, &mut buffers.1,
                |buf, offset| read_exact_at(&file, buf, offset))?;
            write_all_at(&file, &buffers.1, level.output_offset + block * bs as u64)?;
            Ok(())
        };
        (0..blocks).into_par_iter().try_for_each_init(
            || (vec![0u8; bs], vec![0u8; bs]), write_block,
        )?;
    }
    Ok(true)
}

pub(super) struct FecLayout {
    pub data: Range<u64>,
    pub parity: Range<u64>,
    pub rounds: u64,
    pub roots: usize,
    pub symbols: usize,
}

pub(super) fn fec_layout(
    partition: &PartitionUpdate,
    block_size: u32,
    file_len: u64,
) -> Result<Option<FecLayout>> {
    let (data_extent, parity_extent) = match (&partition.fec_data_extent, &partition.fec_extent) {
        (None, None) => return Ok(None),
        (Some(data), Some(parity)) => (data, parity),
        _ => bail!("incomplete FEC extents"),
    };
    if u64::from(block_size) != FEC_BLOCKSIZE {
        bail!("unsupported FEC block size: {block_size} (must be {FEC_BLOCKSIZE})");
    }
    let roots = partition.fec_roots.unwrap_or(2);
    if roots == 0 || roots >= FEC_RSM {
        bail!("invalid fec_roots: {roots} (must be in 1..{FEC_RSM})");
    }
    let data = extent_range(data_extent, block_size)?;
    let parity = extent_range(parity_extent, block_size)?;
    let symbols = FEC_RSM - roots;
    let rounds = ((data.end - data.start) / FEC_BLOCKSIZE).div_ceil(u64::from(symbols));
    let size = rounds.checked_mul(u64::from(roots)).and_then(|n| n.checked_mul(FEC_BLOCKSIZE))
        .context("FEC size overflow")?;
    if size != parity.end - parity.start {
        bail!("FEC extent size mismatch: declared {}, computed {size}", parity.end - parity.start);
    }
    if data.end > file_len || parity.end > file_len {
        bail!("FEC extents exceed partition size");
    }
    if data.start < parity.end && parity.start < data.end {
        bail!("FEC overlaps its data extent");
    }
    if data.is_empty() {
        return Ok(None);
    }
    Ok(Some(FecLayout { data, parity, rounds, roots: roots as usize, symbols: symbols as usize }))
}

/// One reusable Android FEC round (at most 255 * 4096 bytes).
pub(super) struct FecBuffers {
    encoder: RsEncoder,
    block: Vec<u8>,
    columns: Vec<u8>,
    pub parity: Vec<u8>,
}

impl FecBuffers {
    pub fn new(layout: &FecLayout) -> Result<Self> {
        Ok(Self {
            encoder: RsEncoder::try_new(layout.roots).map_err(anyhow::Error::msg)?,
            block: vec![0; FEC_BLOCKSIZE as usize],
            columns: vec![0; FEC_BLOCKSIZE as usize * layout.symbols],
            parity: vec![0; FEC_BLOCKSIZE as usize * layout.roots],
        })
    }

    pub fn encode(
        &mut self,
        layout: &FecLayout,
        round: u64,
        mut read: impl FnMut(&mut [u8], u64) -> std::io::Result<()>,
    ) -> Result<()> {
        let data_blocks = (layout.data.end - layout.data.start) / FEC_BLOCKSIZE;
        for symbol in 0..layout.symbols {
            // Equivalent to Android fec_ecc_interleave(round * rsn * bs + symbol).
            let block = (symbol as u64).checked_mul(layout.rounds)
                .and_then(|n| n.checked_add(round)).context("FEC interleave overflow")?;
            if block < data_blocks {
                read(&mut self.block, layout.data.start + block * FEC_BLOCKSIZE)?;
            } else {
                self.block.fill(0);
            }
            for (column, &byte) in self.block.iter().enumerate() {
                self.columns[column * layout.symbols + symbol] = byte;
            }
        }
        for (data, parity) in self.columns.chunks_exact(layout.symbols)
            .zip(self.parity.chunks_exact_mut(layout.roots))
        {
            self.encoder.encode(data, parity);
        }
        Ok(())
    }
}

/// Generate Reed-Solomon parity, including zero-filled interleave padding.
pub fn compute_and_write_fec(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    if partition.fec_data_extent.is_none() && partition.fec_extent.is_none() {
        return Ok(false);
    }
    let file = std::fs::OpenOptions::new().read(true).write(true).open(output_path)
        .with_context(|| format!("failed to open '{}' for FEC", output_path.display()))?;
    let Some(layout) = fec_layout(partition, block_size, file.metadata()?.len())? else {
        return Ok(false);
    };
    let write_round = |buffers: &mut Result<FecBuffers>, round: u64| -> Result<()> {
        let buffers = buffers.as_mut().map_err(|e| anyhow::anyhow!("{e}"))?;
        buffers.encode(&layout, round, |buf, offset| read_exact_at(&file, buf, offset))?;
        write_all_at(&file, &buffers.parity, layout.parity.start + round * buffers.parity.len() as u64)?;
        Ok(())
    };
    (0..layout.rounds).into_par_iter().try_for_each_init(|| FecBuffers::new(&layout), write_round)?;
    Ok(true)
}

/// Regenerate selected partitions' hash trees and FEC using the same custom
/// output-path mapping as extraction.
pub fn verify_update_partitions(
    partitions: &[&PartitionUpdate],
    output_dir: &Path,
    block_size: u32,
    threads: usize,
    out_config: Option<&HashMap<String, PathBuf>>,
    quiet: bool,
) -> Result<()> {
    if block_size == 0 || block_size > 16 * 1024 * 1024 {
        bail!("invalid block size: {block_size}");
    }
    let update = |partition: &&PartitionUpdate| -> Result<()> {
        let name = &partition.partition_name;
        let output_path = out_config.and_then(|paths| paths.get(name)).cloned()
            .unwrap_or_else(|| output_dir.join(format!("{name}.img")));
        if !std::fs::exists(&output_path)? {
            if !quiet {
                style::elog_skip(name, "file not found");
            }
            return Ok(());
        }
        if compute_and_write_hash_tree(partition, &output_path, block_size)? && !quiet {
            style::elog_ok("HASH", name);
        }
        // FEC metadata may exist independently of hash-tree metadata.
        if compute_and_write_fec(partition, &output_path, block_size)? && !quiet {
            style::elog_ok("FEC", name);
        }
        Ok(())
    };
    let thread_count = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(thread_count).build()
        .context("failed to create thread pool")?;
    pool.install(|| partitions.par_iter().try_for_each(update))
}
