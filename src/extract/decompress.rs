use std::io::Read;

use crate::error::PayloadError;

use super::operation::OpType;

/// Create a streaming decoder for a compressed operation blob.
///
/// The returned reader yields the decompressed bytes on demand; callers read it
/// in bounded chunks so peak memory stays constant regardless of the (possibly
/// multi-gigabyte) decompressed output size. For `Replace` the input is passed
/// through unchanged (the caller normally uses the zero-copy path instead).
pub fn decoder_for<'a, R: Read + 'a>(
    op_type: OpType,
    input: R,
) -> Result<Box<dyn Read + 'a>, PayloadError> {
    Ok(match op_type {
        OpType::Replace => Box::new(input),
        OpType::ReplaceBz => Box::new(bzip2::read::BzDecoder::new(input)),
        OpType::ReplaceXz => Box::new(xz2::read::XzDecoder::new(input)),
        OpType::ReplaceZstd => Box::new(
            zstd::Decoder::new(input)
                .map_err(|e| PayloadError::DecompressionFailed(format!("zstd: {e}")))?,
        ),
        OpType::Zero => Box::new(std::io::empty()),
        other => return Err(PayloadError::UnsupportedOperation(other as i32)),
    })
}
