use std::fs::File;
use std::path::Path;

use crate::error::PayloadError;
use crate::storage::write_all_at;

/// Thread-safe partition writer using positional writes (pwrite/seek_write).
///
/// Multiple threads can write to different offsets concurrently without
/// any locking, as each operation writes to non-overlapping block ranges
/// guaranteed by the OTA format.
pub struct PartitionWriter {
    file: File,
    block_size: u64,
}

impl PartitionWriter {
    /// Create a new partition writer with pre-allocated output file.
    pub fn new(path: &Path, total_size: u64, block_size: u32) -> Result<Self, PayloadError> {
        let file = File::create(path)?;
        // Pre-allocate to avoid fragmentation and repeated metadata updates
        file.set_len(total_size)?;
        Ok(Self {
            file,
            block_size: block_size as u64,
        })
    }

    /// Write data at a specific block offset. Thread-safe without mutex.
    #[inline]
    pub fn write_at_block(&self, data: &[u8], start_block: u64) -> Result<(), PayloadError> {
        let offset = start_block.checked_mul(self.block_size).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "block offset overflow")
        })?;
        self.write_at(data, offset)
    }

    /// Write data at a specific byte offset. Thread-safe without mutex.
    #[inline]
    pub fn write_at(&self, data: &[u8], offset: u64) -> Result<(), PayloadError> {
        write_all_at(&self.file, data, offset)?;
        Ok(())
    }
}
