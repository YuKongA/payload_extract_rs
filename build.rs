fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.compile_protos(
        &[
            "src/proto/update_metadata.proto",
            "src/proto/lz4diff.proto",
        ],
        &["src/proto/"],
    )?;

    Ok(())
}
