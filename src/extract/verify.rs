use sha2::{Digest, Sha256};

use crate::proto::PartitionUpdate;
use crate::storage::ReadOnlyFile;

use super::verify_update::SHA256_DIGEST_SIZE;
use super::verify_update::{FecBuffers, fec_layout, tree_layout};

/// Verify SHA256 hash of data against expected hash.
/// Returns Ok(()) if hashes match or if expected is None.
pub fn verify_sha256(
    data: &[u8],
    expected: &Option<Vec<u8>>,
) -> Result<(), crate::error::PayloadError> {
    if let Some(expected_hash) = expected {
        let actual = Sha256::digest(data);
        if actual.as_slice() != expected_hash.as_slice() {
            return Err(crate::error::PayloadError::HashMismatch {
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual),
            });
        }
    }
    Ok(())
}

/// Verify a partition's declared prefix using its native mapping.
/// A short file fails verification; trailing bytes are not hashed.
pub fn verify_partition(
    path: &std::path::Path,
    expected_hash: &[u8],
    expected_size: u64,
) -> anyhow::Result<bool> {
    verify_partition_file(&ReadOnlyFile::open(path)?, expected_hash, expected_size)
}

/// Verify an already-open partition, allowing tree/FEC checks to reuse its handle.
pub fn verify_partition_file(
    file: &ReadOnlyFile,
    expected_hash: &[u8],
    expected_size: u64,
) -> anyhow::Result<bool> {
    if file.len() < expected_size {
        return Ok(false);
    }
    const CHUNK_SIZE: usize = 4 * 1024 * 1024;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    while offset < expected_size {
        let length = (expected_size - offset).min(CHUNK_SIZE as u64) as usize;
        hasher.update(file.read_range(offset, length)?);
        offset += length as u64;
    }
    Ok(hasher.finalize().as_slice() == expected_hash)
}

/// Verify every salted SHA256 hash and padding byte in the stored dm-verity
/// tree. The root-first layout matches generation; only one expected hash block
/// is buffered, not a partition-sized collection of data-block hashes.
pub fn verify_hash_tree(
    file: &ReadOnlyFile,
    partition: &PartitionUpdate,
    block_size: u32,
) -> anyhow::Result<bool> {
    let Some(levels) = tree_layout(partition, block_size, file.len())? else {
        return Ok(true);
    };
    let bs = block_size as usize;
    let salt = partition.hash_tree_salt.as_deref().unwrap_or(&[]);
    let mut expected = vec![0u8; bs];
    for level in levels {
        for block in 0..level.output_size / u64::from(block_size) {
            expected.fill(0);
            let slots = bs / SHA256_DIGEST_SIZE;
            let first = block * slots as u64;
            let count = level.input_blocks.saturating_sub(first).min(slots as u64);
            for slot in 0..count {
                let input = file.read_range(level.input_offset + (first + slot) * bs as u64, bs)?;
                let mut hasher = Sha256::new();
                hasher.update(salt);
                hasher.update(input);
                let dst = slot as usize * SHA256_DIGEST_SIZE;
                expected[dst..dst + SHA256_DIGEST_SIZE].copy_from_slice(&hasher.finalize());
            }
            let stored = file.read_range(level.output_offset + block * bs as u64, bs)?;
            if stored != expected.as_slice() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Re-encode each interleaved Android Reed-Solomon round and compare all parity
/// bytes. Valid zero parity is accepted; nonzero but corrupt parity is rejected.
pub fn verify_fec(
    file: &ReadOnlyFile,
    partition: &PartitionUpdate,
    block_size: u32,
) -> anyhow::Result<bool> {
    let Some(layout) = fec_layout(partition, block_size, file.len())? else {
        return Ok(true);
    };
    let mut buffers = FecBuffers::new(&layout)?;
    let chunk_size = buffers.parity.len() as u64;
    for round in 0..layout.rounds {
        buffers.encode(&layout, round, |buf, offset| {
            file.read_exact_at(buf, offset)
        })?;
        let stored = file.read_range(
            layout.parity.start + round * chunk_size,
            buffers.parity.len(),
        )?;
        if stored != buffers.parity.as_slice() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::fec::RsEncoder;
    use crate::extract::verify_update::{
        compute_and_write_fec, compute_and_write_hash_tree, verify_update_partitions,
    };
    use crate::proto::Extent;
    use crate::storage::{read_exact_at, write_all_at};
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Image {
        path: PathBuf,
        file: File,
    }

    impl Image {
        fn new(size: u64) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            loop {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = crate::storage::test_dir().join(format!(
                    "payload-verify-{stamp}-{}.img",
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => {
                        file.set_len(size).unwrap();
                        return Self { path, file };
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("creating test image: {e}"),
                }
            }
        }

        fn read_only(&self) -> ReadOnlyFile {
            ReadOnlyFile::open(&self.path).unwrap()
        }
    }

    impl Drop for Image {
        fn drop(&mut self) {
            // Windows permits unlinking ordinary std::fs::File handles once all
            // read-only mappings created by the checks have been dropped.
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn extent(start: u64, blocks: u64) -> Option<Extent> {
        Some(Extent {
            start_block: Some(start),
            num_blocks: Some(blocks),
        })
    }

    #[test]
    fn partition_hash_checks_empty_short_and_prefix() {
        let image = Image::new(0);
        assert!(verify_partition(&image.path, &Sha256::digest([]), 0).unwrap());
        assert!(!verify_partition(&image.path, &Sha256::digest([1]), 1).unwrap());
        write_all_at(&image.file, &[1, 2, 3, 4], 0).unwrap();
        assert!(verify_partition(&image.path, &Sha256::digest([1, 2]), 2).unwrap());
        assert!(!verify_partition(&image.path, &Sha256::digest([1, 3]), 2).unwrap());
    }

    #[test]
    fn tree_layout_matches_independent_multilevel_reference_and_detects_corruption() {
        const BS: usize = 64;
        // Five data blocks need three leaf, two intermediate and one root block.
        let image = Image::new((11 * BS) as u64);
        let data: Vec<u8> = (0..5 * BS).map(|n| (n * 17 + 3) as u8).collect();
        write_all_at(&image.file, &data, 0).unwrap();
        let partition = PartitionUpdate {
            hash_tree_data_extent: extent(0, 5),
            hash_tree_extent: extent(5, 6),
            hash_tree_salt: Some(vec![9, 8, 7]),
            ..Default::default()
        };
        let mut source = data;
        let mut reference_levels = Vec::new();
        loop {
            let mut hashes = Vec::new();
            for block in source.chunks_exact(BS) {
                let mut hash = Sha256::new();
                hash.update([9, 8, 7]);
                hash.update(block);
                hashes.extend_from_slice(&hash.finalize());
            }
            hashes.resize(hashes.len().div_ceil(BS) * BS, 0);
            let root = hashes.len() == BS;
            reference_levels.push(hashes.clone());
            source = hashes;
            if root {
                break;
            }
        }
        let reference: Vec<u8> = reference_levels.into_iter().rev().flatten().collect();
        assert!(compute_and_write_hash_tree(&partition, &image.path, BS as u32).unwrap());
        let mut actual = vec![0u8; reference.len()];
        read_exact_at(&image.file, &mut actual, (5 * BS) as u64).unwrap();
        assert_eq!(actual, reference);
        assert!(verify_hash_tree(&image.read_only(), &partition, BS as u32).unwrap());
        // Corrupt each stored level, including its padding, then restore it.
        for offset in [5 * BS, 6 * BS, 8 * BS, 11 * BS - 1] {
            let original = reference[offset - 5 * BS];
            write_all_at(&image.file, &[original ^ 1], offset as u64).unwrap();
            assert!(!verify_hash_tree(&image.read_only(), &partition, BS as u32).unwrap());
            write_all_at(&image.file, &[original], offset as u64).unwrap();
        }
        write_all_at(&image.file, &[123], 0).unwrap();
        assert!(!verify_hash_tree(&image.read_only(), &partition, BS as u32).unwrap());
    }

    #[test]
    fn fec_checks_all_rounds_and_accepts_zero_parity() {
        const BS: usize = 4096;
        // 254 data blocks span two RS(255,253) rounds, exercising interleaving.
        let image = Image::new((258 * BS) as u64);
        let partition = PartitionUpdate {
            fec_data_extent: extent(0, 254),
            fec_extent: extent(254, 4),
            fec_roots: Some(2),
            ..Default::default()
        };
        assert!(verify_fec(&image.read_only(), &partition, BS as u32).unwrap());
        // Deterministic input, constant within each block, permits an independent
        // column-wise oracle without using the generation layout/round helper.
        for block in 0..254 {
            write_all_at(
                &image.file,
                &vec![(block * 29 + 11) as u8; BS],
                (block * BS) as u64,
            )
            .unwrap();
        }
        assert!(compute_and_write_fec(&partition, &image.path, BS as u32).unwrap());
        let encoder = RsEncoder::new(2);
        for round in 0..2 {
            let mut symbols = [0u8; 253];
            for (symbol, value) in symbols.iter_mut().enumerate() {
                let block = symbol * 2 + round;
                if block < 254 {
                    *value = (block * 29 + 11) as u8;
                }
            }
            let mut parity = [0u8; 2];
            encoder.encode(&symbols, &mut parity);
            let mut actual = vec![0u8; 2 * BS];
            read_exact_at(&image.file, &mut actual, ((254 + round * 2) * BS) as u64).unwrap();
            assert!(actual.chunks_exact(2).all(|column| column == parity));
        }
        assert!(verify_fec(&image.read_only(), &partition, BS as u32).unwrap());
        let parity_offset = (257 * BS + 23) as u64;
        let mut original = [0];
        read_exact_at(&image.file, &mut original, parity_offset).unwrap();
        write_all_at(&image.file, &[original[0] ^ 1], parity_offset).unwrap();
        assert!(!verify_fec(&image.read_only(), &partition, BS as u32).unwrap());
        write_all_at(&image.file, &original, parity_offset).unwrap();
        write_all_at(&image.file, &[99], (253 * BS) as u64).unwrap();
        assert!(!verify_fec(&image.read_only(), &partition, BS as u32).unwrap());
    }

    #[test]
    fn update_honors_custom_paths_and_fec_without_tree() {
        const BS: u64 = 4096;
        let image = Image::new(3 * BS);
        write_all_at(&image.file, &[17], 0).unwrap();
        let partition = PartitionUpdate {
            partition_name: "custom_fec".to_owned(),
            fec_data_extent: extent(0, 1),
            fec_extent: extent(1, 2),
            ..Default::default()
        };
        let paths = HashMap::from([(partition.partition_name.clone(), image.path.clone())]);
        verify_update_partitions(&[&partition], &image.path, BS as u32, 1, Some(&paths), true)
            .unwrap();
        assert!(verify_fec(&image.read_only(), &partition, BS as u32).unwrap());
    }

    #[test]
    fn malformed_metadata_returns_errors() {
        let image = Image::new(4096);
        let mut partition = PartitionUpdate {
            hash_tree_data_extent: extent(u64::MAX, 1),
            hash_tree_extent: extent(0, 1),
            ..Default::default()
        };
        assert!(verify_hash_tree(&image.read_only(), &partition, 4096).is_err());
        assert!(verify_hash_tree(&image.read_only(), &partition, 32).is_err());
        partition = PartitionUpdate {
            fec_data_extent: extent(0, 1),
            fec_extent: extent(1, 2),
            fec_roots: Some(255),
            ..Default::default()
        };
        assert!(verify_fec(&image.read_only(), &partition, 4096).is_err());
        partition.fec_roots = Some(2);
        assert!(verify_fec(&image.read_only(), &partition, 4096).is_err());
        assert!(verify_fec(&image.read_only(), &partition, 512).is_err());
    }
}
