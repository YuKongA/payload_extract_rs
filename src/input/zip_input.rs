use std::io::Cursor;

use anyhow::{Result, bail};
use memmap2::Mmap;

use crate::error::PayloadError;
use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;

/// Open a payload.bin from within a ZIP archive via zero-copy passthrough.
///
/// OTA ZIPs store payload.bin with the STORE method (no compression),
/// so we can locate the entry's data offset and mmap through it directly.
pub fn open_zip(mmap: Mmap) -> Result<PayloadView> {
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = zip::ZipArchive::new(cursor)?;

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
    let mut archive = zip::ZipArchive::new(cursor)?;

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
