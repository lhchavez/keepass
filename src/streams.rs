extern crate crypto;

use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::cmp;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::vec::Vec;

const INNER_STREAM_SALSA20_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

pub fn to_u16(arr: &[u8]) -> u16 {
    assert_eq!(arr.len(), 2);
    return (arr[1] as u16) << 8 | (arr[0] as u16);
}

pub fn to_u32(arr: &[u8]) -> u32 {
    assert_eq!(arr.len(), 4);
    return (arr[3] as u32) << 24 | (arr[2] as u32) << 16 | (arr[1] as u32) << 8 | (arr[0] as u32);
}

pub fn to_u64(arr: &[u8]) -> u64 {
    assert_eq!(arr.len(), 8);
    return (arr[7] as u64) << 56
        | (arr[6] as u64) << 48
        | (arr[5] as u64) << 40
        | (arr[4] as u64) << 32
        | (arr[3] as u64) << 24
        | (arr[2] as u64) << 16
        | (arr[1] as u64) << 8
        | (arr[0] as u64);
}

pub fn read_u8<R: Read>(r: &mut R) -> ::std::io::Result<u8> {
    let mut buf = [0u8; 1];
    try!(r.read_exact(&mut buf));
    return Result::Ok(buf[0]);
}

pub fn read_u16<R: Read>(r: &mut R) -> ::std::io::Result<u16> {
    let mut buf = [0u8; 2];
    try!(r.read_exact(&mut buf));
    return Result::Ok(to_u16(&buf));
}

pub fn read_u32<R: Read>(r: &mut R) -> ::std::io::Result<u32> {
    let mut buf = [0u8; 4];
    try!(r.read_exact(&mut buf));
    return Result::Ok(to_u32(&buf));
}

pub struct AesDecryptor {
    buffer: Vec<u8>,
    pos: usize,
}

impl AesDecryptor {
    pub fn new<R: Read>(inner: &mut R, key: &[u8], iv: &[u8]) -> ::std::io::Result<AesDecryptor> {
        let mut final_result = Vec::<u8>::new();
        let mut cipher = crypto::aes::cbc_decryptor(
            crypto::aes::KeySize::KeySize256,
            key,
            iv,
            crypto::blockmodes::PkcsPadding,
        );

        let mut in_buf = Vec::new();
        try!(inner.read_to_end(&mut in_buf));
        let mut out_buf = [0u8; 4096];

        let mut read_buffer = crypto::buffer::RefReadBuffer::new(&mut in_buf);
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut out_buf);

        loop {
            let result = match cipher.decrypt(&mut read_buffer, &mut write_buffer, true) {
                Result::Err(crypto::symmetriccipher::SymmetricCipherError::InvalidLength) => {
                    return Result::Err(Error::new(ErrorKind::Other, "Invalid length"));
                }
                Result::Err(crypto::symmetriccipher::SymmetricCipherError::InvalidPadding) => {
                    return Result::Err(Error::new(ErrorKind::Other, "Invalid padding"));
                }
                Result::Ok(r) => r,
            };

            final_result.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );

            match result {
                crypto::buffer::BufferResult::BufferUnderflow => break,
                crypto::buffer::BufferResult::BufferOverflow => {}
            };
        }

        return Result::Ok(AesDecryptor {
            buffer: final_result,
            pos: 0,
        });
    }
}

impl Read for AesDecryptor {
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        let r = cmp::min(self.buffer.len() - self.pos, buf.len());
        buf[..r].copy_from_slice(&self.buffer[self.pos..self.pos + r]);
        self.pos += r;
        return Result::Ok(r);
    }
}

impl BufRead for AesDecryptor {
    fn fill_buf(&mut self) -> ::std::io::Result<&[u8]> {
        return Result::Ok(&self.buffer[self.pos..]);
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.buffer.len());
    }
}

pub struct HashedBlockStream<R: Read> {
    inner: R,
    eof: bool,
    buffer: Vec<u8>,
    index: u32,
    pos: usize,
}

impl<R: Read> HashedBlockStream<R> {
    pub fn new(inner: R) -> HashedBlockStream<R> {
        return HashedBlockStream {
            inner: inner,
            eof: false,
            buffer: Vec::<u8>::with_capacity(0),
            index: 0,
            pos: 0,
        };
    }

    fn read_block(&mut self) -> ::std::io::Result<()> {
        assert!(!self.eof);
        let index = try!(read_u32(&mut self.inner));
        if self.index != index {
            return Result::Err(Error::new(ErrorKind::InvalidData, "Invalid block index"));
        }
        let mut expected_hash = [0u8; 32];
        try!(self.inner.read_exact(&mut expected_hash));
        let block_size = try!(read_u32(&mut self.inner));
        let mut buf = vec![0u8; block_size as usize];
        try!(self.inner.read_exact(&mut buf));

        let mut hash = [0u8; 32];
        if block_size > 0 {
            let mut h = crypto::sha2::Sha256::new();
            h.input(buf.as_slice());
            h.result(&mut hash);
        }
        if expected_hash != hash {
            return Result::Err(Error::new(ErrorKind::InvalidData, "Invalid block hash"));
        }

        self.index += 1;
        self.buffer = buf;
        self.pos = 0;
        self.eof = block_size == 0;

        return Result::Ok(());
    }
}

impl<R: Read> Read for HashedBlockStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        if self.eof {
            return Result::Ok(0);
        }
        if self.buffer.len() - self.pos == 0 {
            try!(self.read_block());
        }
        let r = cmp::min(self.buffer.len() - self.pos, buf.len());
        buf[..r].copy_from_slice(&self.buffer[self.pos..self.pos + r]);
        self.pos += r;
        return Result::Ok(r);
    }
}

impl<R: Read> BufRead for HashedBlockStream<R> {
    fn fill_buf(&mut self) -> ::std::io::Result<&[u8]> {
        if self.eof {
            return Result::Ok(&[]);
        }
        if self.buffer.len() - self.pos == 0 {
            try!(self.read_block());
        }
        return Result::Ok(&self.buffer[self.pos..]);
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.buffer.len());
    }
}

pub struct RandomStream {
    cipher: Salsa20,
}

impl RandomStream {
    pub fn new(key: &[u8; 32]) -> RandomStream {
        let mut h = crypto::sha2::Sha256::new();
        h.input(key);

        let mut final_key = [0u8; 32];
        h.result(&mut final_key);
        return RandomStream {
            cipher: Salsa20::new(&final_key, &INNER_STREAM_SALSA20_IV),
        };
    }

    pub fn process(&mut self, buf: &mut [u8]) {
        let mut in_buf = vec![0u8; buf.len()];
        in_buf.copy_from_slice(buf);
        self.cipher.process(&in_buf, buf);
    }
}
