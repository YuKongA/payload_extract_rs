use std::fs::File;
use std::io;
use std::path::Path;

/// Read-only local storage backed by a zero-copy native mapping.
pub struct ReadOnlyFile {
    mapping: Option<memmap2::Mmap>,
    len: u64,
}

impl ReadOnlyFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        // Empty files cannot be mapped, but remain valid read-only storage.
        let mapping = if len == 0 {
            None
        } else {
            Some(unsafe { memmap2::Mmap::map(&file) }?)
        };
        Ok(Self { mapping, len })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        buf.copy_from_slice(self.read_range(offset, buf.len())?);
        Ok(())
    }

    pub fn read_range(&self, offset: u64, length: usize) -> io::Result<&[u8]> {
        self.check_range(offset, length)?;
        let start = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "file offset exceeds address space",
            )
        })?;
        let bytes = self.mapping.as_deref().unwrap_or(&[]);
        Ok(&bytes[start..start + length])
    }

    fn check_range(&self, offset: u64, length: usize) -> io::Result<()> {
        if offset
            .checked_add(length as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "requested range exceeds file length",
            ));
        }
        Ok(())
    }
}

/// Fill a buffer at an absolute file offset, retrying short/interrupted reads.
pub(crate) fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::FileExt;
            file.read_at(buf, offset)
        };
        #[cfg(windows)]
        let result = {
            use std::os::windows::fs::FileExt;
            file.seek_read(buf, offset)
        };
        match result {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short file read",
                ));
            }
            Ok(n) => {
                offset = offset.checked_add(n as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow")
                })?;
                buf = &mut buf[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Write all bytes at an absolute offset; native writes do not share a cursor.
pub(crate) fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
    while !data.is_empty() {
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::FileExt;
            file.write_at(data, offset)
        };
        #[cfg(windows)]
        let result = {
            use std::os::windows::fs::FileExt;
            file.seek_write(data, offset)
        };
        match result {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short file write")),
            Ok(n) => {
                offset = offset.checked_add(n as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow")
                })?;
                data = &data[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_dir() -> std::path::PathBuf {
    std::env::temp_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ranges_are_borrowed_and_bounds_checked() {
        let path = test_dir().join("pe_storage_ranges.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let storage = ReadOnlyFile::open(&path).unwrap();
        assert_eq!(storage.len(), 10);
        let range: &[u8] = storage.read_range(2, 4).unwrap();
        assert_eq!(range, b"2345");
        let mut bytes = [0; 3];
        storage.read_exact_at(&mut bytes, 7).unwrap();
        assert_eq!(&bytes, b"789");
        assert!(storage.read_range(10, 0).unwrap().is_empty());
        assert_eq!(
            storage.read_range(9, 2).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(storage.read_range(u64::MAX, 2).is_err());
        drop(storage);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn positional_helpers_write_and_report_short_reads() {
        let path = test_dir().join("pe_storage_positions.bin");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        write_all_at(&file, b"xyz", 4).unwrap();
        write_all_at(&file, b"ab", 0).unwrap();
        let mut bytes = [0; 7];
        read_exact_at(&file, &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"ab\0\0xyz");
        assert_eq!(
            read_exact_at(&file, &mut bytes, 1).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn empty_file_has_an_empty_borrowed_range() {
        let path = test_dir().join("pe_storage_empty.bin");
        std::fs::write(&path, []).unwrap();
        let storage = ReadOnlyFile::open(&path).unwrap();
        assert_eq!(storage.len(), 0);
        assert!(storage.read_range(0, 0).unwrap().is_empty());
        assert!(storage.read_range(0, 1).is_err());
        drop(storage);
        std::fs::remove_file(path).unwrap();
    }
}
