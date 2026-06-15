pub mod header;

use std::collections::HashMap;

use memmap2::Mmap;
use prost::Message;

use crate::error::PayloadError;
use crate::proto::{DeltaArchiveManifest, PartitionUpdate};

pub use header::{HEADER_SIZE, PayloadHeader};

/// Data backing for PayloadView — either mmap'd file or in-memory buffer.
enum PayloadData {
    Mmap(Mmap),
    Memory(Vec<u8>),
}

impl PayloadData {
    fn as_slice(&self) -> &[u8] {
        match self {
            PayloadData::Mmap(m) => m,
            PayloadData::Memory(v) => v,
        }
    }
}

/// Zero-copy view over a payload file.
///
/// Supports two modes:
/// - **Mmap mode**: the entire payload (or ZIP containing it) is memory-mapped.
/// - **Compact mode** (HTTP): metadata + only needed data ranges are packed
///   contiguously, with an offset remap table so `blob_slice_raw` still works.
pub struct PayloadView {
    data: PayloadData,
    header: PayloadHeader,
    manifest: DeltaArchiveManifest,
    /// Absolute byte offset where data blobs begin (within payload)
    data_offset: u64,
    /// Byte offset of payload within the backing data (non-zero for ZIP passthrough)
    payload_offset: u64,
    /// Offset remap table for compact HTTP mode:
    /// maps (original_data_region_offset, length) → position in backing data.
    /// When present, blob_slice_raw uses this instead of direct indexing.
    remap: Option<HashMap<u64, (u64, u64)>>, // orig_offset -> (compact_pos, length)
    /// Owns resources released after `data` drops — e.g. the HTTP temp file,
    /// deletable only once its mmap is unmapped (required on Windows). Declared
    /// after `data` so it drops last; type-erased to avoid a `tempfile` dep here.
    _guard: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl PayloadView {
    /// Create a PayloadView from a memory-mapped file.
    pub fn from_mmap(mmap: Mmap, payload_offset: u64) -> Result<Self, PayloadError> {
        let data = PayloadData::Mmap(mmap);
        Self::from_data(data, payload_offset, None)
    }

    /// Create a PayloadView from an in-memory buffer with offset remapping.
    /// Used for HTTP selective download where data is packed compactly.
    pub fn from_memory(
        buf: Vec<u8>,
        remap: HashMap<u64, (u64, u64)>,
    ) -> Result<Self, PayloadError> {
        let data = PayloadData::Memory(buf);
        Self::from_data(data, 0, Some(remap))
    }

    /// Like [`from_memory`] but backed by an mmap'd compact temp file instead of
    /// an in-memory buffer, keeping peak memory bounded for large HTTP downloads.
    /// `guard` owns what must outlive the mmap (the temp file, deleted on drop).
    pub fn from_mmap_compact(
        mmap: Mmap,
        remap: HashMap<u64, (u64, u64)>,
        guard: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<Self, PayloadError> {
        let mut view = Self::from_data(PayloadData::Mmap(mmap), 0, Some(remap))?;
        view._guard = Some(guard);
        Ok(view)
    }

    fn from_data(
        data: PayloadData,
        payload_offset: u64,
        remap: Option<HashMap<u64, (u64, u64)>>,
    ) -> Result<Self, PayloadError> {
        let base = payload_offset as usize;
        let slice = &data.as_slice()[base..];

        let header = PayloadHeader::parse(slice)?;

        let manifest_start = HEADER_SIZE;
        let manifest_end = manifest_start + header.manifest_size as usize;

        if slice.len() < manifest_end {
            return Err(PayloadError::PayloadTooSmall {
                expected: base + manifest_end,
                actual: data.as_slice().len(),
            });
        }

        let manifest = DeltaArchiveManifest::decode(&slice[manifest_start..manifest_end])?;
        let data_offset = header.data_offset();

        // Advise the kernel about sequential access pattern for better readahead
        #[cfg(unix)]
        if let PayloadData::Mmap(ref mmap) = data {
            let _ = mmap.advise(memmap2::Advice::Sequential);
        }

        Ok(Self {
            data,
            header,
            manifest,
            data_offset,
            payload_offset,
            remap,
            _guard: None,
        })
    }

    pub fn header(&self) -> &PayloadHeader {
        &self.header
    }

    pub fn manifest(&self) -> &DeltaArchiveManifest {
        &self.manifest
    }

    pub fn block_size(&self) -> u32 {
        self.manifest.block_size.unwrap_or(4096)
    }

    pub fn partitions(&self) -> &[PartitionUpdate] {
        &self.manifest.partitions
    }

    /// Get partitions filtered by name. If `names` is empty, return all.
    pub fn selected_partitions(&self, names: &[String]) -> Vec<&PartitionUpdate> {
        if names.is_empty() {
            self.manifest.partitions.iter().collect()
        } else {
            self.manifest
                .partitions
                .iter()
                .filter(|p| names.iter().any(|n| n == &p.partition_name))
                .collect()
        }
    }

    /// Get data for an operation's blob.
    ///
    /// In mmap mode: zero-copy slice into the mapped region.
    /// In compact/remap mode: looks up the remapped position.
    #[inline]
    pub fn blob_slice_raw(
        &self,
        data_offset: u64,
        data_length: u64,
    ) -> Result<&[u8], PayloadError> {
        let slice = self.data.as_slice();

        if let Some(ref remap) = self.remap {
            // Compact mode: look up remapped position
            if let Some(&(compact_pos, _len)) = remap.get(&data_offset) {
                let start = compact_pos as usize;
                let end = start + data_length as usize;
                return slice.get(start..end).ok_or(PayloadError::PayloadTooSmall {
                    expected: end,
                    actual: slice.len(),
                });
            }
            // Fallback: try direct indexing
        }

        // Mmap mode: direct indexing
        let abs_start =
            self.payload_offset as usize + self.data_offset as usize + data_offset as usize;
        let abs_end = abs_start + data_length as usize;
        slice
            .get(abs_start..abs_end)
            .ok_or(PayloadError::PayloadTooSmall {
                expected: abs_end,
                actual: slice.len(),
            })
    }

    #[allow(dead_code)]
    pub fn metadata_bytes(&self) -> &[u8] {
        let base = self.payload_offset as usize;
        let end = base + HEADER_SIZE + self.header.manifest_size as usize;
        &self.data.as_slice()[base..end]
    }

    #[allow(dead_code)]
    pub fn metadata_signature_bytes(&self) -> Option<&[u8]> {
        if self.header.metadata_signature_size == 0 {
            return None;
        }
        let base = self.payload_offset as usize;
        let start = base + HEADER_SIZE + self.header.manifest_size as usize;
        let end = start + self.header.metadata_signature_size as usize;
        let slice = self.data.as_slice();
        if end <= slice.len() {
            Some(&slice[start..end])
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn metadata_hash(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.metadata_bytes()).to_vec()
    }

    #[allow(dead_code)]
    pub fn payload_signatures_bytes(&self) -> Option<&[u8]> {
        let offset = self.manifest.signatures_offset?;
        let size = self.manifest.signatures_size?;
        let base = self.payload_offset as usize + self.data_offset as usize;
        let start = base + offset as usize;
        let end = start + size as usize;
        let slice = self.data.as_slice();
        if end <= slice.len() {
            Some(&slice[start..end])
        } else {
            None
        }
    }
}

// tempfile is only available under the `http` feature.
#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;
    use crate::payload::header::MAGIC;
    use std::io::Write;

    /// Minimal valid payload metadata: 24-byte header (version 2, empty
    /// manifest, no signature). `DeltaArchiveManifest::decode(&[])` yields a
    /// default manifest, which is enough for `blob_slice_raw` (compact mode
    /// reads via the remap, not the manifest).
    fn minimal_meta() -> Vec<u8> {
        let mut m = Vec::with_capacity(HEADER_SIZE);
        m.extend_from_slice(MAGIC);
        m.extend_from_slice(&2u64.to_be_bytes()); // version
        m.extend_from_slice(&0u64.to_be_bytes()); // manifest_size
        m.extend_from_slice(&0u32.to_be_bytes()); // metadata_signature_size
        m
    }

    /// A compact temp file `[meta][blobA][blobB]` mmap'd via `from_mmap_compact`
    /// must resolve each op's `data_offset` through the remap to the right bytes.
    #[test]
    fn from_mmap_compact_reads_remapped_ranges() {
        let mut file_bytes = minimal_meta();
        let blob_a = [0xAAu8; 16];
        let blob_b = [0xBBu8; 32];

        let pos_a = file_bytes.len() as u64;
        file_bytes.extend_from_slice(&blob_a);
        let pos_b = file_bytes.len() as u64;
        file_bytes.extend_from_slice(&blob_b);

        // Original payload data_offsets (arbitrary) → compact file positions.
        let mut remap = HashMap::new();
        remap.insert(1000u64, (pos_a, blob_a.len() as u64));
        remap.insert(2000u64, (pos_b, blob_b.len() as u64));

        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(&file_bytes).unwrap();
        tf.flush().unwrap();
        let mmap = unsafe { Mmap::map(tf.as_file()).unwrap() };

        let view = PayloadView::from_mmap_compact(mmap, remap, Box::new(tf)).unwrap();

        assert_eq!(view.blob_slice_raw(1000, 16).unwrap(), &blob_a);
        assert_eq!(view.blob_slice_raw(2000, 32).unwrap(), &blob_b);
        // Unknown offset that isn't in the remap falls through to direct
        // indexing and should be out of bounds here.
        assert!(view.blob_slice_raw(9999, 4).is_err());
    }
}
