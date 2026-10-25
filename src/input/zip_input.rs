use std::io::{Read, Seek};

use std::io::Cursor;

use anyhow::{Result, bail};
use memmap2::Mmap;

use crate::error::PayloadError;
use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;

/// Ordinary OTA ZIPs start at zero. Avoid zip's default whole-file offset scan,
/// but retain automatic detection for archives with a prepended stub.
fn open_archive<R: Read + Seek>(mut reader: R) -> zip::result::ZipResult<zip::ZipArchive<R>> {
    let config = zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };
    let metadata =
        zip::ZipArchive::with_config(config, &mut reader).map(|archive| archive.metadata());
    match metadata {
        Ok(metadata) => {
            // SAFETY: this is the exact reader from which the metadata was just
            // parsed; ownership never left this function and no bytes changed.
            Ok(unsafe { zip::ZipArchive::unsafe_new_with_metadata(reader, metadata) })
        }
        Err(_) => zip::ZipArchive::new(reader),
    }
}

/// Open a payload.bin from within a ZIP archive via zero-copy passthrough.
///
/// OTA ZIPs store payload.bin with the STORE method (no compression),
/// so we can locate the entry's data offset and mmap through it directly.
pub fn open_zip(mmap: Mmap) -> Result<PayloadView> {
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = open_archive(cursor)?;

    // Find the payload.bin entry and get its raw data offset
    let payload_offset = {
        let mut found = None;
        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i)?;
            if entry.name().ok().as_deref() == Some("payload.bin") {
                found = entry.data_start();
                break;
            }
        }
        found.ok_or(PayloadError::PayloadNotFoundInZip)?
    };

    Ok(PayloadView::from_mmap(mmap, payload_offset)?)
}

/// Read META-INF/com/android/metadata and metadata.pb from a mmap'd OTA ZIP.
///
/// Both entries are expected to be STORED (uncompressed) in OTA packages.
/// Missing entries are silently skipped; a compressed entry triggers an error.
pub fn read_ota_metadata_from_mmap(mmap: &Mmap) -> Result<OtaMetadataData> {
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = open_archive(cursor)?;

    #[derive(Clone, Copy)]
    enum Kind {
        Text,
        Pb,
    }

    let mut data = OtaMetadataData::default();
    for i in 0..archive.len() {
        // Resolve the entry's slice bounds inside this scope so the `archive`
        // borrow ends before we index into `mmap` for parsing.
        let (start, size, kind) = {
            let entry = archive.by_index_raw(i)?;
            let name = match entry.name() {
                Ok(name) => name,
                Err(_) => continue,
            };
            let kind = match name.as_ref() {
                n if n == ota_metadata::text_entry_name() => Kind::Text,
                n if n == ota_metadata::pb_entry_name() => Kind::Pb,
                _ => continue,
            };
            if entry.compression() != zip::CompressionMethod::Stored {
                bail!(
                    "{} entry is compressed (method {:?}); only STORED is supported",
                    name,
                    entry.compression()
                );
            }
            let Some(start) = entry.data_start() else {
                continue;
            };
            (start, entry.size(), kind)
        };

        let s = start as usize;
        let e = s + size as usize;
        if e > mmap.len() {
            bail!("OTA metadata entry extends past mapped region");
        }
        let slice = &mmap[s..e];
        match kind {
            Kind::Text => {
                data.text = Some(ota_metadata::parse_text(&String::from_utf8_lossy(slice)));
            }
            Kind::Pb => {
                data.pb = Some(ota_metadata::parse_pb_bytes(slice)?);
            }
        }
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, SeekFrom};
    use std::ops::Range;

    /// Sparse virtual archive: reject reads into the payload body so opening a
    /// multi-gigabyte ZIP cannot regress into a linear scan, without large files.
    struct Archive {
        segments: Vec<(u64, Vec<u8>)>,
        position: u64,
        length: u64,
        forbidden: Range<u64>,
    }

    impl Read for Archive {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count =
                (self.length.saturating_sub(self.position)).min(buffer.len() as u64) as usize;
            let end = self.position + count as u64;
            if count > 0 && self.position < self.forbidden.end && end > self.forbidden.start {
                return Err(io::Error::other("ZIP opening read unrelated payload data"));
            }
            buffer[..count].fill(0);
            for (start, bytes) in &self.segments {
                let first = self.position.max(*start);
                let last = end.min(*start + bytes.len() as u64);
                if first < last {
                    buffer[(first - self.position) as usize..(last - self.position) as usize]
                        .copy_from_slice(&bytes[(first - start) as usize..(last - start) as usize]);
                }
            }
            self.position = end;
            Ok(count)
        }
    }

    impl Seek for Archive {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            let position = match position {
                SeekFrom::Start(n) => i128::from(n),
                SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
                SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
            };
            self.position = u64::try_from(position).map_err(|_| io::ErrorKind::InvalidInput)?;
            Ok(self.position)
        }
    }

    fn fixture(zip64: bool, size: u64, prefix: &[u8]) -> (Archive, u64) {
        let name = b"payload.bin";
        let mut extra = Vec::new();
        if zip64 {
            extra.extend_from_slice(&1u16.to_le_bytes());
            extra.extend_from_slice(&16u16.to_le_bytes());
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&size.to_le_bytes());
        }
        let version: u16 = if zip64 { 45 } else { 20 };
        let size32 = if zip64 {
            u32::MAX
        } else {
            u32::try_from(size).unwrap()
        };
        let mut local = 0x04034b50u32.to_le_bytes().to_vec();
        for value in [version, 0, 0, 0, 0] {
            local.extend_from_slice(&value.to_le_bytes());
        }
        // CRC32 of "123456789"; large fixtures only read raw bytes, not CRC.
        local.extend_from_slice(&0xcbf43926u32.to_le_bytes());
        for value in [size32, size32] {
            local.extend_from_slice(&value.to_le_bytes());
        }
        for value in [name.len() as u16, extra.len() as u16] {
            local.extend_from_slice(&value.to_le_bytes());
        }
        local.extend_from_slice(name);
        local.extend_from_slice(&extra);
        let data_start = local.len() as u64;
        let directory_start = data_start + size;

        let mut directory = 0x02014b50u32.to_le_bytes().to_vec();
        for value in [version, version, 0, 0, 0, 0] {
            directory.extend_from_slice(&value.to_le_bytes());
        }
        for value in [0xcbf43926, size32, size32] {
            directory.extend_from_slice(&value.to_le_bytes());
        }
        for value in [name.len() as u16, extra.len() as u16, 0, 0, 0] {
            directory.extend_from_slice(&value.to_le_bytes());
        }
        for value in [0u32, 0] {
            directory.extend_from_slice(&value.to_le_bytes());
        }
        directory.extend_from_slice(name);
        directory.extend_from_slice(&extra);
        let directory_size = directory.len() as u64;
        if zip64 {
            let eocd64_offset = directory_start + directory_size;
            directory.extend_from_slice(&0x06064b50u32.to_le_bytes());
            directory.extend_from_slice(&44u64.to_le_bytes());
            for value in [version, version] {
                directory.extend_from_slice(&value.to_le_bytes());
            }
            for value in [0u32, 0] {
                directory.extend_from_slice(&value.to_le_bytes());
            }
            for value in [1u64, 1, directory_size, directory_start] {
                directory.extend_from_slice(&value.to_le_bytes());
            }
            directory.extend_from_slice(&0x07064b50u32.to_le_bytes());
            directory.extend_from_slice(&0u32.to_le_bytes());
            directory.extend_from_slice(&eocd64_offset.to_le_bytes());
            directory.extend_from_slice(&1u32.to_le_bytes());
        }
        directory.extend_from_slice(&0x06054b50u32.to_le_bytes());
        let count: u16 = if zip64 { u16::MAX } else { 1 };
        for value in [0u16, 0, count, count] {
            directory.extend_from_slice(&value.to_le_bytes());
        }
        directory.extend_from_slice(&(directory_size as u32).to_le_bytes());
        directory.extend_from_slice(
            &(if zip64 {
                u32::MAX
            } else {
                directory_start as u32
            })
            .to_le_bytes(),
        );
        directory.extend_from_slice(&0u16.to_le_bytes());

        let base = prefix.len() as u64;
        let length = base + directory_start + directory.len() as u64;
        let forbidden = base + data_start + 9..length.saturating_sub(65557);
        (
            Archive {
                segments: vec![
                    (0, prefix.to_vec()),
                    (base, local),
                    (base + data_start, b"123456789".to_vec()),
                    (base + directory_start, directory),
                ],
                position: 0,
                length,
                forbidden,
            },
            base + data_start,
        )
    }

    #[test]
    fn opens_zip32_and_large_zip64_without_reading_the_payload_body() {
        for (zip64, size) in [(false, 1024 * 1024), (true, 5 * 1024 * 1024 * 1024)] {
            let (reader, offset) = fixture(zip64, size, &[]);
            let mut archive = open_archive(reader).unwrap();
            let mut entry = archive.by_index_raw(0).unwrap();
            assert_eq!(entry.name().unwrap(), "payload.bin");
            assert_eq!(entry.size(), size);
            assert_eq!(entry.data_start(), Some(offset));
            let mut bytes = [0; 9];
            entry.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"123456789");
        }
    }

    #[test]
    fn preserves_prepended_stub_detection_for_zip32_and_zip64() {
        for zip64 in [false, true] {
            let (mut reader, offset) = fixture(zip64, 9, b"MZstub-prefix");
            reader.forbidden = 0..0;
            let mut archive = open_archive(reader).unwrap();
            let mut entry = archive.by_name("payload.bin").unwrap();
            assert_eq!(entry.data_start(), Some(offset));
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"123456789");
        }
    }

    #[test]
    fn rejects_corrupt_central_directories() {
        for zip64 in [false, true] {
            let (mut reader, _) = fixture(zip64, 9, &[]);
            reader.forbidden = 0..0;
            reader.segments.last_mut().unwrap().1[..4].fill(0);
            assert!(open_archive(reader).is_err());
        }
    }
}
