extern crate crypto;

use crypto::digest::Digest;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::path::Path;

pub trait Key {
    fn key(&self) -> &[u8];
}

pub struct PasswordKey {
    key: [u8; 32],
}

impl PasswordKey {
    pub fn new(key: &str) -> PasswordKey {
        let mut h = crypto::sha2::Sha256::new();
        h.input_str(key);
        let mut hash = [0u8; 32];
        h.result(&mut hash);
        return PasswordKey { key: hash };
    }
}

impl Key for PasswordKey {
    fn key(&self) -> &[u8] {
        return &self.key;
    }
}

pub struct CompositeKey {
    key: [u8; 32],
}

impl CompositeKey {
    pub fn new(keys: &[&[u8]]) -> CompositeKey {
        let mut h = crypto::sha2::Sha256::new();
        for key in keys {
            h.input(key)
        }
        let mut hash = [0u8; 32];
        h.result(&mut hash);
        return CompositeKey { key: hash };
    }

    pub fn new_from_file<P: AsRef<Path>>(path: P) -> ::std::io::Result<CompositeKey> {
        let mut file = File::open(path)?;
        let mut hash = [0u8; 32];
        file.read_exact(&mut hash)?;
        return Result::Ok(CompositeKey { key: hash });
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> ::std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(self.key())?;
        return Result::Ok(());
    }

    pub fn transform(
        &self,
        transform_seed: &[u8; 32],
        transform_rounds: u64,
    ) -> ::std::io::Result<[u8; 32]> {
        let mut buffer = [0u8; 32];
        let mut out_buffer = [0u8; 32];
        for i in 0..self.key.len() {
            out_buffer[i] = self.key[i];
        }
        for _ in 0..transform_rounds {
            for i in 0..buffer.len() {
                buffer[i] = out_buffer[i];
            }
            let mut cipher = crypto::aes::ecb_encryptor(
                crypto::aes::KeySize::KeySize256,
                transform_seed,
                crypto::blockmodes::NoPadding,
            );
            let mut read_buffer = crypto::buffer::RefReadBuffer::new(&buffer);
            let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut out_buffer);
            loop {
                match cipher.encrypt(&mut read_buffer, &mut write_buffer, true) {
                    Result::Err(crypto::symmetriccipher::SymmetricCipherError::InvalidLength) => {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::Other,
                            "Invalid length",
                        ));
                    }
                    Result::Err(crypto::symmetriccipher::SymmetricCipherError::InvalidPadding) => {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::Other,
                            "Invalid padding",
                        ));
                    }
                    Result::Ok(crypto::buffer::BufferResult::BufferUnderflow) => break,
                    Result::Ok(crypto::buffer::BufferResult::BufferOverflow) => {
                        panic!("Should never overflow");
                    }
                };
            }
        }

        let mut h = crypto::sha2::Sha256::new();
        h.input(&out_buffer);
        let mut hash = [0u8; 32];
        h.result(&mut hash);

        return Result::Ok(hash);
    }
}

impl Key for CompositeKey {
    fn key(&self) -> &[u8] {
        return &self.key;
    }
}

#[cfg(test)]
mod test {
    use keys::Key;

    fn to_hex_string(buf: &[u8]) -> String {
        let result: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();
        return result.join("");
    }

    #[test]
    fn test_password_key() {
        let key = ::keys::PasswordKey::new("test");
        assert_eq!(
            to_hex_string(key.key()),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        let composite = ::keys::CompositeKey::new(&[key.key()]);
        assert_eq!(
            to_hex_string(composite.key()),
            "954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4"
        );
        let seed = [0u8; 32];
        let transformed = composite.transform(&seed, 2).unwrap();
        assert_eq!(
            to_hex_string(&transformed),
            "23cc601af4e2606cdf6cace2b73d7bd6026d78dc2b4792d8b346b0c010e7b76d"
        );
    }

    #[test]
    fn test_password_file_key() {
        let composite = ::keys::CompositeKey::new_from_file("./data/password.key").unwrap();
        assert_eq!(
            to_hex_string(composite.key()),
            "954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4"
        );
        let seed = [0u8; 32];
        let transformed = composite.transform(&seed, 2).unwrap();
        assert_eq!(
            to_hex_string(&transformed),
            "23cc601af4e2606cdf6cace2b73d7bd6026d78dc2b4792d8b346b0c010e7b76d"
        );
    }
}
