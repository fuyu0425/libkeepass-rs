use byteorder::WriteBytesExt;
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use std::convert::{TryFrom, TryInto};

use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    crypt,
    db::{DBVersion, Database, Header, InnerHeader},
    hmac_block_stream, parse,
    result::{DatabaseIntegrityError, Error, Result},
    variant_dictionary::VariantDictionary,
    xml_parse,
};

use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug, PartialEq)]
pub struct KDBX4Header {
    // https://gist.github.com/msmuenchen/9318327
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub outer_iv: Vec<u8>,
    pub kdf: KdfSettings,
    pub body_start: usize,
}

#[derive(Debug, PartialEq)]
pub struct BinaryAttachment {
    flags: u8,
    content: Vec<u8>,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum InnerHeaderFieldType {
    END = 0,
    RANDOM_STREAM_ID = 1,
    RANDOM_STREAM_KEY = 2,
    BINARY_ATTACHMENT = 3,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum OuterHeaderFieldType {
    END = 0,
    COMMENT = 1,
    CIPHERID = 2,
    COMPRESSIONFLAGS = 3,
    MASTERSEED = 4,
    ENCRYPTIONIV = 7,
    KDFPARAMS = 11,
}

impl TryFrom<&[u8]> for BinaryAttachment {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let flags = data[0];
        let content = data[1..].to_vec();

        Ok(BinaryAttachment { flags, content })
    }
}
impl From<&BinaryAttachment> for Vec<u8> {
    fn from(b: &BinaryAttachment) -> Vec<u8> {
        let mut res = Vec::new();
        res.push(b.flags);
        res.extend(&b.content);
        res
    }
}

#[derive(Debug, PartialEq)]
pub struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherSuite,
    inner_random_stream_key: Vec<u8>,
    binaries: Vec<BinaryAttachment>,
    body_start: usize,
}

impl KDBX4InnerHeader {
    pub(crate) fn decryptor(&self) -> Result<Box<dyn crypt::ciphers::Cipher>> {
        Ok(self
            .inner_random_stream
            .get_cipher(&self.inner_random_stream_key)?)
    }
}

fn parse_outer_header(data: &[u8]) -> Result<KDBX4Header> {
    let (version, file_major_version, file_minor_version) = crate::parse::get_kdbx_version(data)?;

    if version != 0xb54b_fb67 || file_major_version != 4 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version,
            file_minor_version,
        }
        .into());
    }

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf: Option<KdfSettings> = None;

    // parse header
    let mut pos = 12;

    loop {
        // parse header blocks.
        //
        // every block is a triplet of (3 + entry_length) bytes with this structure:
        //
        // (
        //   entry_type: u8,                        // a numeric entry type identifier
        //   entry_length: u32,                     // length of the entry buffer
        //   entry_buffer: [u8; entry_length]       // the entry buffer
        // )

        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match FromPrimitive::from_u8(entry_type) {
            // END - finished parsing header
            Some(OuterHeaderFieldType::END) => {
                break;
            }

            // COMMENT
            Some(OuterHeaderFieldType::COMMENT) => {}

            // CIPHERID - a UUID specifying which cipher suite
            //            should be used to encrypt the payload
            Some(OuterHeaderFieldType::CIPHERID) => {
                outer_cipher = Some(OuterCipherSuite::try_from(entry_buffer)?);
            }

            // COMPRESSIONFLAGS - first byte determines compression of payload
            Some(OuterHeaderFieldType::COMPRESSIONFLAGS) => {
                compression = Some(Compression::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            // MASTERSEED - Master seed for deriving the master key
            Some(OuterHeaderFieldType::MASTERSEED) => master_seed = Some(entry_buffer.to_vec()),

            // ENCRYPTIONIV - Initialization Vector for decrypting the payload
            Some(OuterHeaderFieldType::ENCRYPTIONIV) => outer_iv = Some(entry_buffer.to_vec()),

            // KDF Parameters
            Some(OuterHeaderFieldType::KDFPARAMS) => {
                let vd = VariantDictionary::parse(entry_buffer)?;
                kdf = Some(KdfSettings::try_from(vd)?);
            }

            None => {
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteOuterHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf = get_or_err(kdf, "Key Derivation Function Parameters")?;

    Ok(KDBX4Header {
        version,
        file_major_version,
        file_minor_version,
        outer_cipher,
        compression,
        master_seed,
        outer_iv,
        kdf,
        body_start: pos,
    })
}

fn parse_inner_header(data: &[u8]) -> Result<KDBX4InnerHeader> {
    let mut pos = 0;

    let mut inner_random_stream = None;
    let mut inner_random_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match FromPrimitive::from_u8(entry_type) {
            Some(InnerHeaderFieldType::END) => break,
            Some(InnerHeaderFieldType::RANDOM_STREAM_ID) => {
                inner_random_stream = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }
            Some(InnerHeaderFieldType::RANDOM_STREAM_KEY) => {
                inner_random_stream_key = Some(entry_buffer.to_vec())
            }
            Some(InnerHeaderFieldType::BINARY_ATTACHMENT) => {
                let binary = BinaryAttachment::try_from(entry_buffer)?;
                binaries.push(binary);
            }
            None => {
                return Err(DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteInnerHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream UUID")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    Ok(KDBX4InnerHeader {
        inner_random_stream,
        inner_random_stream_key,
        binaries,
        body_start: pos,
    })
}
fn serialize_inner_header(header: &KDBX4InnerHeader) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = vec![];
    let mut random_stream: Vec<u8> = vec![];

    random_stream.write_u32::<LittleEndian>((&header.inner_random_stream).into())?;
    write_value_inner_header(
        &mut buf,
        InnerHeaderFieldType::RANDOM_STREAM_ID,
        &random_stream,
    );

    write_value_inner_header(
        &mut buf,
        InnerHeaderFieldType::RANDOM_STREAM_KEY,
        &header.inner_random_stream_key,
    );
    for binary in &header.binaries {
        let b_buf: Vec<u8> = binary.into();
        write_value_inner_header(&mut buf, InnerHeaderFieldType::BINARY_ATTACHMENT, &b_buf);
    }
    write_value_inner_header(&mut buf, InnerHeaderFieldType::END, &[]);
    Ok(buf)
}

/// This function will _grow_ buf by the necessary amount and write to it
fn write_value_header(buf: &mut Vec<u8>, field_type: u8, data: &[u8]) {
    buf.push(ToPrimitive::to_u8(&field_type).unwrap());
    buf.write_u32::<LittleEndian>(data.len().try_into().unwrap())
        .unwrap();
    buf.extend(data);
}

/// This function will _grow_ buf by the necessary amount and write to it
fn write_value_inner_header(buf: &mut Vec<u8>, field_type: InnerHeaderFieldType, data: &[u8]) {
    write_value_header(buf, ToPrimitive::to_u8(&field_type).unwrap(), data)
}

/// This function will _grow_ buf by the necessary amount and write to it
fn write_value_outer_header(buf: &mut Vec<u8>, field_type: OuterHeaderFieldType, data: &[u8]) {
    write_value_header(buf, ToPrimitive::to_u8(&field_type).unwrap(), data)
}
fn serialize_outer_header(header: &KDBX4Header) -> Vec<u8> {
    let mut vec = vec![0; 12];
    vec[0..4].copy_from_slice(&parse::KDBX_IDENTIFIER);
    // version
    LittleEndian::write_u32(&mut vec[4..], 0xb54b_fb67);
    // minor version
    LittleEndian::write_u16(&mut vec[8..], 0);
    // major version
    LittleEndian::write_u16(&mut vec[10..], 4);

    let cs: Vec<u8> = (&header.outer_cipher).into();
    write_value_outer_header(&mut vec, OuterHeaderFieldType::CIPHERID, &cs);

    let mut cr: [u8; 4] = [0, 0, 0, 0];
    LittleEndian::write_u32(&mut cr, (&header.compression).into());
    write_value_outer_header(&mut vec, OuterHeaderFieldType::COMPRESSIONFLAGS, &cr);

    write_value_outer_header(
        &mut vec,
        OuterHeaderFieldType::MASTERSEED,
        &header.master_seed,
    );

    write_value_outer_header(
        &mut vec,
        OuterHeaderFieldType::ENCRYPTIONIV,
        &header.outer_iv,
    );

    let kdf_dict: VariantDictionary = (&header.kdf).into();
    let kdf_settings: Vec<u8> = kdf_dict.serialize().unwrap();
    write_value_outer_header(&mut vec, OuterHeaderFieldType::KDFPARAMS, &kdf_settings);
    write_value_outer_header(
        &mut vec,
        OuterHeaderFieldType::END,
        &vec![13, 10, 13, 10], // "\r\n\r\n" is what keepassxc writes
    );
    vec
}

/// Open, decrypt and parse a KeePass database from a source and key elements
pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    let (header, inner_header, xml) = decrypt_xml(data, key_elements)?;

    // Initialize inner decryptor from inner header params
    let mut inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    let (root, meta) = xml_parse::parse_xml_block(&xml, &mut *inner_decryptor)?;

    let db = Database {
        header: Header::KDBX4(header),
        inner_header: InnerHeader::KDBX4(inner_header),
        root,
        meta,
        version: DBVersion::KDB4,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX4 database from a source and key elements
pub(crate) fn decrypt_xml(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<(KDBX4Header, KDBX4InnerHeader, Vec<u8>)> {
    // parse header
    let header = parse_outer_header(data)?;
    let pos = header.body_start;

    // split file into segments:
    //      header_data         - The outer header data
    //      header_sha256       - A Sha256 hash of header_data (for verification of header integrity)
    //      header_hmac         - A HMAC of the header_data (for verification of the key_elements)
    //      hmac_block_stream   - A HMAC-verified block stream of encrypted and compressed blocks
    let header_data = &data[0..pos];
    let header_sha256 = &data[pos..(pos + 32)];
    let header_hmac = &data[(pos + 32)..(pos + 64)];
    let hmac_block_stream = &data[(pos + 64)..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..pos]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(Error::IncorrectKey);
    }

    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(&payload_encrypted)?;
    let payload = header
        .compression
        .get_compression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let inner_header = parse_inner_header(&payload)?;

    // after inner header is one XML document
    let xml = &payload[inner_header.body_start..];

    Ok((header, inner_header, xml.to_vec()))
}

/// Encrypt a KeePass KDBX4 database from representation and key elements
pub(crate) fn encrypt_xml(d: &Database, key_elements: Vec<u8>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    if let Header::KDBX4(h) = &d.header {
        payload.extend(serialize_outer_header(&h));

        let composite_key = crypt::calculate_sha256(&[key_elements.as_slice()]).unwrap();
        let transformed_key = h.kdf.get_kdf().transform_key(&composite_key).unwrap();
        let hmac_key =
            crypt::calculate_sha512(&[&h.master_seed, &transformed_key, b"\x01"]).unwrap();
        let header_hmac_key =
            hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key).unwrap();
        let header_hmac = crypt::calculate_hmac(&[&payload], &header_hmac_key).unwrap();
        let header_sha256 = crypt::calculate_sha256(&[payload.as_slice()]).unwrap();
        let master_key =
            crypt::calculate_sha256(&[h.master_seed.as_ref(), &transformed_key]).unwrap();

        payload.extend(header_sha256.as_slice());
        payload.extend(header_hmac.as_slice());
        // start with payload

        let mut inner_payload = vec![];

        let mut inner_encryptor = d.get_decryptor().unwrap();
        let xml = xml_parse::write_xml(&d, &mut *inner_encryptor).unwrap();

        // inner header
        if let InnerHeader::KDBX4(ih) = &d.inner_header {
            inner_payload.extend(serialize_inner_header(&ih).unwrap());
        }
        inner_payload.extend(xml);

        let payload_compressed = h
            .compression
            .get_compression()
            .compress(&inner_payload)
            .unwrap();
        let payload_encrypted = h
            .outer_cipher
            .get_cipher(&master_key, h.outer_iv.as_ref())
            .unwrap()
            .encrypt(&payload_compressed)
            .unwrap();

        let payload_hmacd =
            hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key).unwrap();
        payload.extend(payload_hmacd);
    } else {
        panic!("expected kdb4");
    }

    Ok(payload)
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use crate::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        db::{Database, Node},
        parse::kdbx4::*,
        result::Result,
    };
    use std::{fs::File, path::Path};

    use hex_literal::hex;

    #[test]
    fn test_encrypt_decrypt_xml() -> Result<()> {
        let mut key_elements: Vec<Vec<u8>> = Vec::new();

        key_elements.push(
            crypt::calculate_sha256(&["demopass".as_bytes()])?
                .as_slice()
                .to_vec(),
        );

        let key_elements: Vec<u8> = key_elements.into_iter().flatten().collect();

        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        let encrypted = encrypt_xml(&db, key_elements.clone()).unwrap();
        let parsed_db = parse(&encrypted, &[key_elements]).unwrap();

        assert_eq!(parsed_db.inner_header, db.inner_header);
        assert_eq!(parsed_db.meta, db.meta);
        assert_eq!(parsed_db.version, db.version);
        assert_eq!(parsed_db.header, db.header);

        assert_eq!(parsed_db.root.name, db.root.name);
        assert_eq!(parsed_db.root.children.len(), db.root.children.len());

        for i in 0..parsed_db.root.children.len() {
            let p_child = &parsed_db.root.children[i];
            let orig_child = &db.root.children[i];
            match p_child {
                Node::Entry(e) => {
                    if let Node::Entry(og) = orig_child {
                        assert_eq!(og.uuid, e.uuid);
                        assert_eq!(og.fields, e.fields);
                        assert_eq!(og.unhandled_fields, e.unhandled_fields);
                    } else {
                        panic!("aaa");
                    }
                }
                Node::Group(g) => {
                    if let Node::Group(og) = orig_child {
                        assert_eq!(og.name, g.name);
                        assert_eq!(og.uuid, g.uuid);
                        assert_eq!(og.unhandled_fields, g.unhandled_fields);
                    } else {
                        panic!("bbb");
                    }
                }
            }
            assert_eq!(p_child, orig_child);
        }
        assert_eq!(parsed_db.root, db.root);

        assert_eq!(parsed_db, db);
        Ok(())
    }

    #[test]
    fn test_write_and_parse_outer_header() -> Result<()> {
        // AES256
        let cipherdata: Vec<u8> = hex!("31c1f2e6bf714350be5805216afc5aff").into();
        let cipher = OuterCipherSuite::try_from(&cipherdata[..]).unwrap();
        let header = KDBX4Header {
            version: 0xb54b_fb67,
            file_major_version: 4,
            file_minor_version: 0,
            outer_cipher: cipher,
            compression: Compression::GZip,
            master_seed: Vec::new(),
            body_start: 127,
            kdf: KdfSettings::Aes {
                rounds: 1,
                seed: Vec::new(),
            },
            outer_iv: Vec::new(),
        };
        let bytes = serialize_outer_header(&header);
        let parsed = parse_outer_header(&bytes)?;
        assert_eq!(header, parsed);
        Ok(())
    }

    #[test]
    fn test_write_and_parse_inner_header() -> Result<()> {
        let h = KDBX4InnerHeader {
            binaries: vec![],
            body_start: 25,
            inner_random_stream: InnerCipherSuite::ChaCha20,
            inner_random_stream_key: vec![1, 2, 3, 4, 5, 6],
        };
        let serialized = serialize_inner_header(&h).unwrap();
        let parsed = parse_inner_header(&serialized).unwrap();
        assert_eq!(h, parsed);
        Ok(())
    }
}
