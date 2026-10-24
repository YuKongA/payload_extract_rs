use super::{ExtractConfig, extract_partition_to_file};
use crate::payload::PayloadView;
use crate::proto::install_operation::Type;
use crate::proto::{
    DeltaArchiveManifest, Extent, InstallOperation, PartitionInfo, PartitionUpdate,
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

fn extent(start_block: u64) -> Extent {
    Extent {
        start_block: Some(start_block),
        num_blocks: Some(1),
    }
}

fn payload(corrupt_hash: bool) -> PayloadView {
    let mut hash = Sha256::digest(b"test").to_vec();
    if corrupt_hash {
        hash[0] ^= 1;
    }
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        partitions: vec![PartitionUpdate {
            partition_name: "system".into(),
            new_partition_info: Some(PartitionInfo {
                size: Some(16),
                ..Default::default()
            }),
            operations: vec![
                InstallOperation {
                    r#type: Type::Replace as i32,
                    data_offset: Some(0),
                    data_length: Some(4),
                    data_sha256_hash: Some(hash),
                    dst_extents: vec![extent(2)],
                    ..Default::default()
                },
                InstallOperation {
                    r#type: Type::Replace as i32,
                    data_offset: Some(4),
                    data_length: Some(4),
                    dst_extents: vec![extent(0)],
                    ..Default::default()
                },
                InstallOperation {
                    r#type: Type::Zero as i32,
                    dst_extents: vec![extent(1)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"CrAU").unwrap();
    input.write_all(&2u64.to_be_bytes()).unwrap();
    input
        .write_all(&(manifest.len() as u64).to_be_bytes())
        .unwrap();
    input.write_all(&0u32.to_be_bytes()).unwrap();
    input.write_all(&manifest).unwrap();
    input.write_all(b"testdata").unwrap();
    PayloadView::from_mmap(unsafe { memmap2::Mmap::map(&input) }.unwrap(), 0).unwrap()
}

fn config(verify_ops: bool) -> ExtractConfig {
    ExtractConfig {
        verify_ops,
        threads: 2,
        quiet: true,
        source_dir: None,
        out_config: None,
        progress: None,
    }
}

#[test]
fn open_file_output_truncates_stale_bytes_and_preserves_owner_and_cursor() {
    let mut output = tempfile::tempfile().unwrap();
    output.write_all(&[0xff; 64]).unwrap();
    output.seek(SeekFrom::Start(7)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ignored_path = directory.path().join("not-the-output.img");
    let mut options = config(true);
    options.out_config = Some(HashMap::from([("system".into(), ignored_path.clone())]));

    extract_partition_to_file(&payload(false), &output, "system", &options).unwrap();

    assert_eq!(output.stream_position().unwrap(), 7);
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"data\0\0\0\0test\0\0\0\0");
    assert!(!ignored_path.exists());
    output.seek(SeekFrom::Start(0)).unwrap();
    output.write_all(b"live").unwrap();
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut first = [0; 4];
    output.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"live");
}

#[test]
fn missing_partition_does_not_discard_existing_output() {
    let mut output = tempfile::tempfile().unwrap();
    output.write_all(b"keep").unwrap();
    assert!(extract_partition_to_file(&payload(false), &output, "missing", &config(true)).is_err());
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"keep");
}

#[test]
fn open_file_output_preserves_operation_verification() {
    let source = payload(true);
    let mut output = tempfile::tempfile().unwrap();
    assert!(extract_partition_to_file(&source, &output, "system", &config(true)).is_err());
    extract_partition_to_file(&source, &output, "system", &config(false)).unwrap();
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"data\0\0\0\0test\0\0\0\0");
}
