fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();

     match protoc_bin_vendored::protoc_bin_path() {
         Ok(protoc) => {
             config.protoc_executable(protoc);
         }
         Err(err) => {
             println!(
                 "cargo:warning=Unable to use vendored protoc ({}); falling back to PROTOC or `protoc` on PATH",
                 err
             );
         }
     }

    config.compile_protos(
        &["src/proto/update_metadata.proto", "src/proto/lz4diff.proto"],
        &["src/proto/"],
    )?;

    Ok(())
}
