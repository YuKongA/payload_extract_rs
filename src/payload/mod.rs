pub mod header;

use std::io;
use std::collections::HashMap;

use memmap2::Mmap;
use prost::Message;

use crate::error::PayloadError;
use crate::proto::{DeltaArchiveManifest, PartitionUpdate};

pub use header::{HEADER_SIZE, PayloadHeader};

/// Native mappings or compact HTTP buffers.
enum PayloadData {
    Mmap(Mmap),
    #[cfg(feature = "http")]
    Memory(Vec<u8>),
}

impl PayloadData {
    fn as_slice(&self) -> &[u8] {
        match self {
            PayloadData::Mmap(m) => m,
            #[cfg(feature = "http")]
            PayloadData::Memory(v) => v,
        }
    }
}

/// Parsed payload metadata and access to its operation data.
/// Native files use zero-copy mappings.
/// Compact HTTP inputs resolve operation offsets through a remap table.
pub struct PayloadView {
    data: PayloadData,
    header: PayloadHeader,
    manifest: DeltaArchiveManifest,
    /// Absolute byte offset where data blobs begin (within payload)
    data_offset: u64,
    /// Byte offset of payload within the backing data (non-zero for ZIP passthrough)
    payload_offset: u64,
    /// Strict compact-mode lookup: original data offset -> (file position, max
    /// operation length). Missing offsets must never index unrelated cache data.
    remap: Option<HashMap<u64, (u64, u64)>>,
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
    #[cfg(feature = "http")]
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
    #[cfg(feature = "http")]
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
        let base = usize::try_from(payload_offset).map_err(|_| invalid_range())?;
        let slice = data.as_slice().get(base..).ok_or_else(invalid_range)?;

        let header = PayloadHeader::parse(slice)?;

        let manifest_start = HEADER_SIZE;
        let manifest_end = usize::try_from(header.manifest_size).ok()
            .and_then(|size| manifest_start.checked_add(size)).ok_or_else(invalid_range)?;

        if slice.len() < manifest_end {
            return Err(PayloadError::PayloadTooSmall {
                expected: base + manifest_end,
                actual: data.as_slice().len(),
            });
        }

        let manifest = DeltaArchiveManifest::decode(&slice[manifest_start..manifest_end])?;
        let data_offset = (manifest_end as u64).checked_add(header.metadata_signature_size as u64).ok_or_else(invalid_range)?;

        // Advise the kernel about sequential access pattern for better readahead
        #[cfg(unix)]
        #[allow(irrefutable_let_patterns)]
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

    /// Borrow an operation blob directly from the backing mapping or buffer.
    #[inline]
    pub fn blob_slice_raw(
        &self,
        data_offset: u64,
        data_length: u64,
    ) -> Result<&[u8], PayloadError> {
        self.read_range(self.blob_start(data_offset, data_length)?, data_length)
    }

    fn blob_start(&self, data_offset: u64, data_length: u64) -> Result<u64, PayloadError> {
        if let Some(remap) = &self.remap {
            // Empty operation blobs need no cached bytes, even when their
            // unused original offset is outside the selected data region.
            if data_length == 0 {
                return Ok(self.data_offset);
            }
            let &(position, length) = remap.get(&data_offset).ok_or_else(invalid_range)?;
            if data_length > length {
                return Err(invalid_range());
            }
            Ok(position)
        } else {
            self.payload_offset.checked_add(self.data_offset)
                .and_then(|offset| offset.checked_add(data_offset)).ok_or_else(invalid_range)
        }
    }

    /// A bounded reader over one operation, independent of the OTA's total size.
    pub fn blob_reader_raw(&self, data_offset: u64, data_length: u64) -> Result<io::Cursor<&[u8]>, PayloadError> {
        self.blob_slice_raw(data_offset, data_length).map(io::Cursor::new)
    }

    fn read_range(&self, start: u64, length: u64) -> Result<&[u8], PayloadError> {
        let end = start.checked_add(length).ok_or_else(invalid_range)?;
        let start = usize::try_from(start).map_err(|_| invalid_range())?;
        let end = usize::try_from(end).map_err(|_| invalid_range())?;
        let slice = self.data.as_slice();
        slice.get(start..end).ok_or(PayloadError::PayloadTooSmall {
            expected: end,
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
    pub fn payload_signatures_bytes(&self) -> Result<Option<&[u8]>, PayloadError> {
        let (Some(offset), Some(size)) = (self.manifest.signatures_offset, self.manifest.signatures_size) else {
            return Ok(None);
        };
        self.blob_slice_raw(offset, size).map(Some)
    }
}

fn invalid_range() -> PayloadError {
    io::Error::new(io::ErrorKind::InvalidData, "payload range is truncated, too large, or overflows").into()
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
        // An unselected original range would land on blob A if direct indexing
        // were allowed, so test an in-bounds alias as well as an absent range.
        assert!(view.blob_slice_raw(0, 4).is_err());
        assert!(view.blob_reader_raw(0, 4).is_err());
        assert!(view.blob_slice_raw(9999, 4).is_err());
        assert!(view.blob_slice_raw(1000, 17).is_err());
        assert!(view.blob_reader_raw(1000, 17).is_err());
        assert!(view.blob_slice_raw(u64::MAX, 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = crate::storage::test_dir().join(format!("payload-ranges-{stamp}-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir(&dir).unwrap();
            let mut bytes = b"CrAU".to_vec();
            bytes.extend_from_slice(&2u64.to_be_bytes());
            bytes.extend_from_slice(&0u64.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes.extend_from_slice(b"abcXYZ");
            std::fs::write(dir.join("payload.bin"), bytes).unwrap();
            Self(dir)
        }

        fn open(&self) -> PayloadView {
            crate::input::open(self.0.join("payload.bin").to_str().unwrap(), false, None).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn operation_readers_are_bounded_and_can_be_interleaved() {
        let fixture = Fixture::new();
        let view = fixture.open();
        let mut first: io::Cursor<&[u8]> = view.blob_reader_raw(0, 3).unwrap();
        let mut second = view.blob_reader_raw(3, 3).unwrap();
        let mut byte = [0];
        first.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"a");
        second.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"X");
        let mut rest = Vec::new();
        first.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"bc");
        rest.clear();
        second.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"YZ");
        assert_eq!(first.read(&mut byte).unwrap(), 0);
        assert_eq!(view.blob_slice_raw(2, 3).unwrap(), b"cXY");
    }

    #[test]
    fn payload_signature_ranges_are_borrowed_and_bounds_checked() {
        let fixture = Fixture::new();
        let mut view = fixture.open();
        assert!(view.payload_signatures_bytes().unwrap().is_none());
        view.manifest.signatures_offset = Some(3);
        view.manifest.signatures_size = Some(3);
        let signatures: &[u8] = view.payload_signatures_bytes().unwrap().unwrap();
        assert_eq!(signatures, b"XYZ");
        assert_eq!(signatures.as_ptr(), view.blob_slice_raw(3, 3).unwrap().as_ptr());
        view.manifest.signatures_size = Some(4);
        assert!(view.payload_signatures_bytes().is_err());
    }

    #[test]
    fn truncated_and_overflowing_blob_ranges_return_errors() {
        let fixture = Fixture::new();
        let view = fixture.open();
        for (offset, length) in [(5, 2), (u64::MAX, 2), (0, u64::MAX)] {
            assert!(view.blob_slice_raw(offset, length).is_err());
            assert!(view.blob_reader_raw(offset, length).is_err());
        }
        assert_eq!(view.blob_reader_raw(6, 0).unwrap().read(&mut [0; 1]).unwrap(), 0);
    }
}
