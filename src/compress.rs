use super::result::Result;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

pub trait Compressible: Decompress + Compress {}
pub trait Decompress {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>>;
}
pub trait Compress {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>>;
}

pub struct NoCompression;

impl Decompress for NoCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Decompress for GZipCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        let mut decoder = GzDecoder::new(in_buffer);
        decoder.read_to_end(&mut res)?;
        Ok(res)
    }
}

impl Compress for NoCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        Ok(in_buffer.to_vec())
    }
}
impl Compressible for NoCompression {}
impl Compressible for GZipCompression {}

impl Compress for GZipCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(in_buffer)?;
        Ok(encoder.finish().unwrap())
    }
}

#[test]
fn test_decompress_compress_decompress() -> Result<()> {
    let data = "hi this is a test";
    let bdata: Vec<u8> = data.as_bytes().to_vec();
    let compressed = GZipCompression.compress(&bdata)?;
    let decompressed = GZipCompression.decompress(&compressed)?;
    assert_eq!(bdata, decompressed);
    Ok(())
}
