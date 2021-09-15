use crate::result::{DatabaseIntegrityError, Result};
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use cipher::generic_array::{typenum::U64, GenericArray};

/// Read from a HMAC block stream into a raw buffer
pub(crate) fn read_hmac_block_stream(data: &[u8], key: &GenericArray<u8, U64>) -> Result<Vec<u8>> {
    // keepassxc src/streams/HmacBlockStream.cpp

    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index: u64 = 0;

    while pos < data.len() {
        let hmac = &data[pos..(pos + 32)];
        let size_bytes = &data[(pos + 32)..(pos + 36)];
        let size = LittleEndian::read_u32(size_bytes) as usize;
        let block = &data[(pos + 36)..(pos + 36 + size)];

        // verify block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key)?;
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index as u64);

        if hmac
            != crate::crypt::calculate_hmac(
                &[&block_index_buf, size_bytes, &block],
                &hmac_block_key,
            )?
            .as_slice()
        {
            return Err(DatabaseIntegrityError::BlockHashMismatch { block_index }.into());
        }

        pos += 36 + size;
        block_index += 1;

        out.extend_from_slice(block);
    }

    Ok(out)
}

pub(crate) fn get_hmac_block_key(
    block_index: u64,
    key: &GenericArray<u8, U64>,
) -> Result<GenericArray<u8, U64>> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index as u64);
    crate::crypt::calculate_sha512(&[&buf, key])
}

pub(crate) fn write_hmac_block_stream(data: &[u8], key: &GenericArray<u8, U64>) -> Result<Vec<u8>> {
    assert!(data.len() < u32::max_value() as usize);
    // by asserting that we have at most 2^32-1 bytes
    // we know that there is only 1 block to encode
    let mut out = Vec::new();
    let mut block_index = 0;

    for _data in [data, &[]] {
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index as u64);
        let hmac_block_key = get_hmac_block_key(block_index, key)?;

        let mut size_bytes = vec![];
        size_bytes.write_u32::<LittleEndian>(_data.len() as u32)?;

        let hmac = crate::crypt::calculate_hmac(
            &[&block_index_buf, &size_bytes, &_data],
            &hmac_block_key,
        )?;

        out.extend_from_slice(&hmac);
        out.extend_from_slice(&size_bytes);
        out.extend_from_slice(_data);
        block_index += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::hmac_block_stream::*;

    #[test]
    fn test_write_read_block_stream() -> Result<()> {
        let key = vec![
            224, 95, 188, 106, 17, 40, 69, 115, 82, 107, 32, 22, 252, 108, 42, 100, 180, 183, 12,
            213, 183, 185, 166, 183, 219, 132, 225, 255, 35, 136, 170, 164, 96, 154, 8, 141, 167,
            173, 115, 112, 56, 143, 60, 88, 37, 190, 194, 156, 30, 129, 89, 58, 1, 21, 241, 206,
            243, 175, 23, 187, 119, 116, 92, 240,
        ];
        let val = "this is a test string".as_bytes().to_vec();
        let gkey = GenericArray::from_slice(&key);
        let enc = write_hmac_block_stream(&val, &gkey).unwrap();
        let dec = read_hmac_block_stream(&enc, &gkey).unwrap();
        assert_eq!(val, dec);
        Ok(())
    }
}
