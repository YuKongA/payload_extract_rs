use std::collections::HashMap;

use anyhow::{Result, bail, ensure};

const MERGE_GAP: u64 = 256 * 1024;

/// A remote data-region range and its absolute location in the compact file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DownloadRange {
    pub data_offset: u64,
    pub length: u64,
    pub file_offset: u64,
}

/// The compact file is `[header + manifest + metadata signature][ranges…]`.
#[derive(Debug)]
pub(crate) struct CompactPlan {
    pub total_size: u64,
    pub download_bytes: u64,
    pub ranges: Vec<DownloadRange>,
    pub remap: HashMap<u64, (u64, u64)>,
}

/// Sort and pack operation ranges. A known payload length includes metadata.
pub(crate) fn plan_compact(
    metadata_length: u64,
    mut operations: Vec<(u64, u64)>,
    payload_length: Option<u64>,
) -> Result<CompactPlan> {
    if let Some(length) = payload_length {
        ensure!(
            metadata_length <= length,
            "payload metadata exceeds payload length"
        );
    }
    operations.retain(|&(_, length)| length != 0);
    for &(offset, length) in &operations {
        let end = offset
            .checked_add(length)
            .and_then(|end| metadata_length.checked_add(end))
            .ok_or_else(|| anyhow::anyhow!("operation data range overflows"))?;
        if let Some(payload_length) = payload_length {
            ensure!(
                end <= payload_length,
                "operation data range exceeds payload length"
            );
        }
    }
    operations.sort_unstable();
    // Each offset must retain the longest requested blob.
    operations.dedup_by(|next, previous| {
        if next.0 == previous.0 {
            previous.1 = previous.1.max(next.1);
            true
        } else {
            false
        }
    });

    let mut ranges: Vec<DownloadRange> = Vec::with_capacity(operations.len());
    for &(offset, length) in &operations {
        if let Some(last) = ranges.last_mut() {
            let end = last.data_offset + last.length;
            if offset <= end || offset - end <= MERGE_GAP {
                last.length = end.max(offset + length) - last.data_offset;
                continue;
            }
        }
        ranges.push(DownloadRange {
            data_offset: offset,
            length,
            file_offset: 0,
        });
    }
    let mut total_size = metadata_length;
    for range in &mut ranges {
        range.file_offset = total_size;
        total_size = total_size
            .checked_add(range.length)
            .ok_or_else(|| anyhow::anyhow!("compact file length overflows"))?;
    }
    let mut remap = HashMap::with_capacity(operations.len());
    let mut range_index = 0;
    for (offset, length) in operations {
        while range_index < ranges.len()
            && offset >= ranges[range_index].data_offset + ranges[range_index].length
        {
            range_index += 1;
        }
        let Some(range) = ranges.get(range_index) else {
            bail!("operation data is not covered by compact layout");
        };
        ensure!(
            offset >= range.data_offset && offset + length <= range.data_offset + range.length,
            "operation data is not covered by compact layout"
        );
        remap.insert(
            offset,
            (range.file_offset + (offset - range.data_offset), length),
        );
    }
    Ok(CompactPlan {
        total_size,
        download_bytes: total_size - metadata_length,
        ranges,
        remap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_unsorted_and_duplicate_ranges_have_deterministic_layout() {
        let plan = plan_compact(
            24,
            vec![(200, 30), (100, 10), (110, 40), (100, 50), (100, 10)],
            None,
        )
        .unwrap();
        assert_eq!(
            plan.ranges,
            vec![DownloadRange {
                data_offset: 100,
                length: 130,
                file_offset: 24
            }]
        );
        assert_eq!(plan.total_size, 154);
        assert_eq!(plan.download_bytes, 130);
        assert_eq!(plan.remap[&100], (24, 50));
        assert_eq!(plan.remap[&110], (34, 40));
        assert_eq!(plan.remap[&200], (124, 30));
        let reversed = plan_compact(
            24,
            vec![(100, 10), (100, 50), (110, 40), (100, 10), (200, 30)],
            None,
        )
        .unwrap();
        assert_eq!(plan.ranges, reversed.ranges);
        assert_eq!(plan.remap, reversed.remap);
    }

    #[test]
    fn coalescing_includes_exact_gap_boundary_only() {
        let merged = plan_compact(0, vec![(0, 10), (10 + MERGE_GAP, 1)], None).unwrap();
        assert_eq!(merged.ranges.len(), 1);
        assert_eq!(merged.total_size, MERGE_GAP + 11);
        let separate = plan_compact(24, vec![(0, 10), (11 + MERGE_GAP, 1)], None).unwrap();
        assert_eq!(separate.ranges.len(), 2);
        assert_eq!(separate.total_size, 35);
        assert_eq!(separate.remap[&(11 + MERGE_GAP)], (34, 1));
    }

    #[test]
    fn far_offsets_do_not_create_sparse_files() {
        let far = 9_000_000_000;
        let plan = plan_compact(24, vec![(far, 16), (0, 4)], Some(far + 40)).unwrap();
        assert_eq!(plan.total_size, 44);
        assert_eq!(plan.download_bytes, 20);
        assert_eq!(plan.remap[&far], (28, 16));
    }

    #[test]
    fn no_data_needs_only_metadata_even_for_zero_length_operations() {
        let plan = plan_compact(24, vec![(u64::MAX, 0), (0, 0)], Some(24)).unwrap();
        assert_eq!(plan.total_size, 24);
        assert_eq!(plan.download_bytes, 0);
        assert!(plan.ranges.is_empty());
        assert!(plan.remap.is_empty());
    }

    #[test]
    fn overflowing_or_out_of_payload_ranges_are_rejected() {
        assert!(plan_compact(0, vec![(u64::MAX, 1)], None).is_err());
        assert!(plan_compact(24, vec![(u64::MAX - 24, 1)], None).is_err());
        assert!(plan_compact(24, vec![(4, 2)], Some(29)).is_err());
        assert!(plan_compact(24, vec![], Some(23)).is_err());
        assert_eq!(
            plan_compact(24, vec![(4, 2)], Some(30)).unwrap().total_size,
            26
        );
        let edge = plan_compact(0, vec![(u64::MAX - 1, 1)], Some(u64::MAX)).unwrap();
        assert_eq!(edge.total_size, 1);
        let far = plan_compact(0, vec![(0, 8), (u64::MAX - 1, 1)], Some(u64::MAX)).unwrap();
        assert_eq!(far.total_size, 9);
        assert_eq!(far.remap[&(u64::MAX - 1)], (8, 1));
        let near_end = plan_compact(0, vec![(u64::MAX - 10, 1), (u64::MAX - 1, 1)], None).unwrap();
        assert_eq!(near_end.ranges.len(), 1);
        assert_eq!(near_end.download_bytes, 10);
        assert_eq!(near_end.remap[&(u64::MAX - 1)], (9, 1));
    }
}
