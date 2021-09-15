use hex_literal::hex;
use std::collections::HashMap;
use std::convert::{From, TryFrom};

use crate::{
    compress, crypt,
    result::{DatabaseIntegrityError, Error, Result},
    variant_dictionary::VariantDictionary,
    variant_dictionary::VariantDictionaryValue,
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

#[derive(Debug, PartialEq)]
pub enum OuterCipherSuite {
    AES256,
    Twofish,
    ChaCha20,
}

impl OuterCipherSuite {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn crypt::ciphers::Cipher>> {
        match self {
            OuterCipherSuite::AES256 => Ok(Box::new(crypt::ciphers::AES256Cipher::new(key, iv)?)),
            OuterCipherSuite::Twofish => Ok(Box::new(crypt::ciphers::TwofishCipher::new(key, iv)?)),
            OuterCipherSuite::ChaCha20 => Ok(Box::new(crypt::ciphers::ChaCha20Cipher::new_key_iv(
                key, iv,
            )?)),
        }
    }
}

impl From<&OuterCipherSuite> for Vec<u8> {
    fn from(c: &OuterCipherSuite) -> Vec<u8> {
        match c {
            OuterCipherSuite::AES256 => CIPHERSUITE_AES256.to_vec(),
            OuterCipherSuite::Twofish => CIPHERSUITE_TWOFISH.to_vec(),
            OuterCipherSuite::ChaCha20 => CIPHERSUITE_CHACHA20.to_vec(),
        }
    }
}
impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else if v == CIPHERSUITE_TWOFISH {
            Ok(OuterCipherSuite::Twofish)
        } else if v == CIPHERSUITE_CHACHA20 {
            Ok(OuterCipherSuite::ChaCha20)
        } else {
            Err(DatabaseIntegrityError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}

impl InnerCipherSuite {
    pub(crate) fn get_cipher(&self, key: &[u8]) -> Result<Box<dyn crypt::ciphers::Cipher>> {
        match self {
            InnerCipherSuite::Plain => Ok(Box::new(crypt::ciphers::PlainCipher::new(key)?)),
            InnerCipherSuite::Salsa20 => Ok(Box::new(crypt::ciphers::Salsa20Cipher::new(key)?)),
            InnerCipherSuite::ChaCha20 => Ok(Box::new(crypt::ciphers::ChaCha20Cipher::new(key)?)),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            3 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(DatabaseIntegrityError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

impl From<&InnerCipherSuite> for u32 {
    fn from(i: &InnerCipherSuite) -> u32 {
        match i {
            InnerCipherSuite::Plain => 0,
            InnerCipherSuite::Salsa20 => 2,
            InnerCipherSuite::ChaCha20 => 3,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        memory: u64,
        salt: Vec<u8>,
        iterations: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
    pub(crate) fn get_kdf(&self) -> Box<dyn crypt::kdf::Kdf> {
        match self {
            KdfSettings::Aes { seed, rounds } => Box::new(crypt::kdf::AesKdf {
                seed: seed.clone(),
                rounds: *rounds,
            }),
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => Box::new(crypt::kdf::Argon2Kdf {
                memory: *memory,
                salt: salt.clone(),
                iterations: *iterations,
                parallelism: *parallelism,
                version: *version,
            }),
        }
    }
}

const KDF_AES_KDBX3: [u8; 16] = hex!("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

impl TryFrom<VariantDictionary> for KdfSettings {
    type Error = Error;

    fn try_from(vd: VariantDictionary) -> Result<KdfSettings> {
        let uuid: Vec<u8> = vd.get("$UUID")?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get("M")?;
            let salt: Vec<u8> = vd.get("S")?;
            let iterations: u64 = vd.get("I")?;
            let parallelism: u32 = vd.get("P")?;
            let version: u32 = vd.get("V")?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => {
                    return Err(Error::from(DatabaseIntegrityError::InvalidKDFVersion {
                        version,
                    }))
                }
            };

            Ok(KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            })
        } else if uuid == KDF_AES_KDBX4 || uuid == KDF_AES_KDBX3 {
            let rounds: u64 = vd.get("R")?;
            let seed: Vec<u8> = vd.get("S")?;

            Ok(KdfSettings::Aes { rounds, seed })
        } else {
            Err(DatabaseIntegrityError::InvalidKDFUUID { uuid }.into())
        }
    }
}
impl From<&KdfSettings> for VariantDictionary {
    fn from(ks: &KdfSettings) -> VariantDictionary {
        let mut data = HashMap::<String, VariantDictionaryValue>::new();
        match ks {
            KdfSettings::Aes { seed, rounds } => {
                data.insert(
                    "$UUID".to_string(),
                    VariantDictionaryValue::ByteArray(KDF_AES_KDBX3.to_vec()),
                );
                // The only official UUID for this KDF is the KDBX3 one
                // https://sourceforge.net/p/keepass/discussion/329220/thread/8df9a61d7f/?limit=25#f8f7
                data.insert("R".to_string(), VariantDictionaryValue::UInt64(*rounds));
                data.insert(
                    "S".to_string(),
                    VariantDictionaryValue::ByteArray(seed.clone()),
                );
            }
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => {
                let mut data = HashMap::<String, VariantDictionaryValue>::new();
                data.insert(
                    "$UUID".to_string(),
                    VariantDictionaryValue::ByteArray(KDF_ARGON2.to_vec()),
                );
                data.insert("M".to_string(), VariantDictionaryValue::UInt64(*memory));
                data.insert(
                    "S".to_string(),
                    VariantDictionaryValue::ByteArray(salt.clone()),
                );
                data.insert("I".to_string(), VariantDictionaryValue::UInt64(*iterations));
                data.insert(
                    "P".to_string(),
                    VariantDictionaryValue::UInt32(*parallelism),
                );

                let version = match version {
                    argon2::Version::Version10 => 0x10,
                    argon2::Version::Version13 => 0x13,
                };
                data.insert("V".to_string(), VariantDictionaryValue::UInt32(version));
            }
        };
        VariantDictionary { data }
    }
}

#[derive(Debug, PartialEq)]
pub enum Compression {
    None,
    GZip,
}

impl Compression {
    pub(crate) fn get_compression(&self) -> Box<dyn compress::Compressible> {
        match self {
            // This has to return a decompressable/compressable
            Compression::None => Box::new(compress::NoCompression),
            Compression::GZip => Box::new(compress::GZipCompression),
        }
    }
}

impl TryFrom<u32> for Compression {
    type Error = Error;

    fn try_from(v: u32) -> Result<Compression> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(DatabaseIntegrityError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}

impl From<&Compression> for u32 {
    fn from(c: &Compression) -> u32 {
        match c {
            Compression::None => 0,
            Compression::GZip => 1,
        }
    }
}
