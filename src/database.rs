extern crate base64;
extern crate crypto;
extern crate flate2;
extern crate regex;
extern crate sxd_document;

use crypto::digest::Digest;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::path::Path;
use std::vec::Vec;
use sxd_document::dom::{ChildOfElement, ChildOfRoot, Element, Root};
use sxd_document::parser;

const SIGNATURE_1: u32 = 0x9AA2D903;
const SIGNATURE_2: u32 = 0xB54BFB67;
const CIPHER_AES: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const SALSA20: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

enum CompressionAlgorithm {
    None = 0,
    GZip = 1,
}

#[allow(dead_code)]
enum HeaderFieldID {
    EndOfHeader = 0,
    Comment = 1,
    CipherID = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIV = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamID = 10,
}

struct DatabaseHeader {
    #[allow(dead_code)]
    version: u32,
    master_seed: [u8; 32],
    transform_seed: [u8; 32],
    transform_rounds: u64,
    encryption_iv: [u8; 16],
    protected_stream_key: [u8; 32],
    stream_start_bytes: Vec<u8>,
    compression_algorithm: CompressionAlgorithm,
}

impl DatabaseHeader {
    pub fn new(mut file: &mut File) -> ::std::io::Result<DatabaseHeader> {
        if ::streams::read_u32(&mut file)? != SIGNATURE_1 {
            return Result::Err(::std::io::Error::new(
                ErrorKind::InvalidData,
                "Signature 1 mismatch",
            ));
        }
        if ::streams::read_u32(&mut file)? != SIGNATURE_2 {
            return Result::Err(::std::io::Error::new(
                ErrorKind::InvalidData,
                "Signature 2 mismatch",
            ));
        }

        let mut header = DatabaseHeader {
            version: ::streams::read_u32(&mut file)?,
            compression_algorithm: CompressionAlgorithm::None,
            master_seed: [0u8; 32],
            transform_seed: [0u8; 32],
            transform_rounds: 0,
            encryption_iv: [0u8; 16],
            protected_stream_key: [0u8; 32],
            stream_start_bytes: Vec::new(),
        };

        header.read_headers(&mut file)?;

        return Result::Ok(header);
    }

    fn read_headers(&mut self, mut file: &mut File) -> ::std::io::Result<()> {
        loop {
            let (id, data) = DatabaseHeader::read_header(&mut file)?;
            match id {
                HeaderFieldID::EndOfHeader => break,
                HeaderFieldID::Comment => {}
                HeaderFieldID::CipherID => {
                    if data != CIPHER_AES {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Unsupported cipher: {:?}", data),
                        ));
                    }
                }
                HeaderFieldID::CompressionFlags => {
                    if data.len() != 4 {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid compression flags: {:?}", data),
                        ));
                    }
                    match ::streams::to_u32(data.as_slice()) {
                        0 => {
                            self.compression_algorithm = CompressionAlgorithm::None;
                        }
                        1 => {
                            self.compression_algorithm = CompressionAlgorithm::GZip;
                        }
                        algorithm_id => {
                            return Result::Err(::std::io::Error::new(
                                ErrorKind::InvalidData,
                                format!("Invalid compression algorithm: {:?}", algorithm_id),
                            ));
                        }
                    }
                }
                HeaderFieldID::MasterSeed => {
                    if data.len() != self.master_seed.len() {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid master seed: {:?}", data),
                        ));
                    }
                    self.master_seed.clone_from_slice(data.as_slice());
                }
                HeaderFieldID::TransformSeed => {
                    if data.len() != self.transform_seed.len() {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid transform seed: {:?}", data),
                        ));
                    }
                    self.transform_seed.clone_from_slice(data.as_slice());
                }
                HeaderFieldID::TransformRounds => {
                    if data.len() != 8 {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid transform rounds: {:?}", data),
                        ));
                    }
                    self.transform_rounds = ::streams::to_u64(data.as_slice());
                }
                HeaderFieldID::EncryptionIV => {
                    if data.len() != self.encryption_iv.len() {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid encryption IV: {:?}", data),
                        ));
                    }
                    self.encryption_iv.clone_from_slice(data.as_slice());
                }
                HeaderFieldID::ProtectedStreamKey => {
                    if data.len() != self.protected_stream_key.len() {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid protected stream key: {:?}", data),
                        ));
                    }
                    self.protected_stream_key.clone_from_slice(data.as_slice());
                }
                HeaderFieldID::StreamStartBytes => {
                    self.stream_start_bytes = data;
                }
                HeaderFieldID::InnerRandomStreamID => {
                    if data != SALSA20 {
                        return Result::Err(::std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Unsupported random stream ID: {:?}", data),
                        ));
                    }
                }
            }
        }
        return Result::Ok(());
    }

    fn read_header(mut file: &File) -> ::std::io::Result<(HeaderFieldID, Vec<u8>)> {
        let raw_id = ::streams::read_u8(&mut file)?;
        let len = ::streams::read_u16(&mut file)?;
        let mut data = Vec::<u8>::with_capacity(len as usize);
        data.resize(len as usize, 0u8);
        file.read_exact(data.as_mut_slice())?;
        if raw_id > HeaderFieldID::InnerRandomStreamID as u8 {
            return Result::Err(::std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid header ID",
            ));
        }
        let id: HeaderFieldID = unsafe { ::std::mem::transmute(raw_id) };
        return Result::Ok((id, data));
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProtectedString {
    pub password: Vec<u8>,
    pub mask: Vec<u8>,
}

impl ProtectedString {
    pub fn clear(s: &mut String) {
        let ptr = s.as_mut_ptr();

        for i in 0..s.capacity() as isize {
            unsafe { *ptr.offset(i) = 0 };
        }
        s.truncate(0);
    }
}

/// XOR plaintext and keystream, storing the result in dst.
pub fn xor_keystream(dst: &mut [u8], plaintext: &[u8], keystream: &[u8]) {
    assert!(dst.len() == plaintext.len());
    assert!(plaintext.len() <= keystream.len());

    // Do one byte at a time, using unsafe to skip bounds checking.
    let p = plaintext.as_ptr();
    let k = keystream.as_ptr();
    let d = dst.as_mut_ptr();
    for i in 0isize..plaintext.len() as isize {
        unsafe { *d.offset(i) = *p.offset(i) ^ *k.offset(i) };
    }
}

impl std::convert::From<&ProtectedString> for std::string::String {
    fn from(value: &ProtectedString) -> Self {
        let mut buf = vec![0u8; value.password.len()];
        xor_keystream(
            buf.as_mut_slice(),
            value.password.as_slice(),
            value.mask.as_slice(),
        );
        match String::from_utf8(buf) {
            Ok(password) => password,
            Err(_) => String::from("Error decoding utf-8"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    ProtectedString(ProtectedString),
    String(String),
}

impl std::convert::From<Value> for std::string::String {
    fn from(value: Value) -> Self {
        match value {
            Value::ProtectedString(s) => String::from(&s),
            Value::String(s) => s,
        }
    }
}

impl std::convert::From<&Value> for std::string::String {
    fn from(value: &Value) -> Self {
        match value {
            Value::ProtectedString(s) => String::from(s),
            Value::String(s) => String::from(s),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub uuid: String,
    pub notes: String,
    pub password: Value,
    pub title: String,
    pub url: String,
    pub user_name: String,
}

#[derive(Debug)]
pub struct Group {
    pub uuid: String,
    pub name: String,
    pub notes: String,
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,
}

pub struct Database {
    #[allow(dead_code)]
    header: DatabaseHeader,
    #[allow(dead_code)]
    package: sxd_document::Package,
    pub groups: Vec<Group>,
}

fn find_element_by_tag_name<'a>(root: &'a Root, name: &str) -> Option<Element<'a>> {
    fn find_element_by_tag_name_internal<'a>(
        element: Element<'a>,
        name: &str,
    ) -> Option<Element<'a>> {
        for child in element.children() {
            if let ChildOfElement::Element::<'a>(e) = child {
                if e.name().local_part() == name {
                    return Some(e);
                }
                if let Some(e) = find_element_by_tag_name_internal(e, name) {
                    return Some(e);
                }
            }
        }

        return None;
    }

    for child in root.children() {
        if let ChildOfRoot::Element::<'a>(e) = child {
            if e.name().local_part() == name {
                return Some(e);
            }
            if let Some(f) = find_element_by_tag_name_internal(e, name) {
                return Some(f);
            }
        }
    }

    return None;
}

fn text_child(element: &Element, name: &str) -> Option<String> {
    if element.name().local_part() == name {
        for child in element.children() {
            if let ChildOfElement::Text(t) = child {
                return Some(String::from(t.text()));
            }
        }
    }
    return None;
}

fn element_children<'a>(element: &Element<'a>) -> Vec<Element<'a>> {
    let mut vec = Vec::<Element>::new();
    for child in element.children() {
        if let ChildOfElement::Element(e) = child {
            vec.push(e);
        }
    }
    vec
}

impl Database {
    pub fn open<P: AsRef<Path>>(
        path: P,
        key: &::keys::CompositeKey,
    ) -> ::std::io::Result<Database> {
        let mut file = File::open(path)?;

        let header = DatabaseHeader::new(&mut file)?;

        let master_key = key.transform(&header.transform_seed, header.transform_rounds)?;

        let mut h = crypto::sha2::Sha256::new();
        h.input(&header.master_seed);
        h.input(&master_key);
        let mut final_key = [0u8; 32];
        h.result(&mut final_key);

        let mut cipher =
            ::streams::AesDecryptor::new(&mut file, &final_key, &header.encryption_iv)?;

        let mut start_bytes = [0u8; 32];
        cipher.read_exact(&mut start_bytes)?;
        if start_bytes != header.stream_start_bytes.as_slice() {
            return Result::Err(::std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Invalid key: {:?}", start_bytes),
            ));
        }

        let mut hashed_stream = ::streams::HashedBlockStream::new(cipher);

        let mut decompressor: Box<dyn (::std::io::Read)> = match header.compression_algorithm {
            CompressionAlgorithm::None => Box::new(&mut hashed_stream),
            CompressionAlgorithm::GZip => {
                Box::new(flate2::bufread::GzDecoder::new(&mut hashed_stream))
            }
        };

        let mut xml_buf = Vec::<u8>::new();
        decompressor.read_to_end(&mut xml_buf)?;
        let xml_str = match ::std::str::from_utf8(xml_buf.as_slice()) {
            Result::Err(err) => {
                return Result::Err(::std::io::Error::new(
                    ErrorKind::InvalidData,
                    err.description(),
                ));
            }
            Result::Ok(s) => s,
        };

        //println!("{}", xml_str);

        let mut random_stream = ::streams::RandomStream::new(&header.protected_stream_key);

        let package = match parser::parse(xml_str) {
            Result::Err(err) => {
                return Result::Err(::std::io::Error::new(ErrorKind::InvalidData, err));
            }
            Result::Ok(package) => package,
        };

        let mut groups = Vec::<Group>::new();
        {
            let document = package.as_document();
            let root = document.root();
            let root_element = find_element_by_tag_name(&root, "Root").ok_or(
                ::std::io::Error::new(ErrorKind::InvalidData, "Root node not found"),
            )?;
            for ref child in element_children(&root_element) {
                if child.name().local_part() != "Group" {
                    continue;
                }
                groups.push(Database::parse_group(child, &mut random_stream));
            }
        }

        return Result::Ok(Database {
            header: header,
            package: package,
            groups: groups,
        });
    }

    pub fn find_entry_by_uuid<'a>(&'a self, name: &str) -> Option<&'a Entry> {
        fn find_entry_by_uuid_internal<'a>(group: &'a Group, name: &str) -> Option<&'a Entry> {
            for entry in &group.entries {
                if entry.uuid == name {
                    return Some(entry);
                }
            }
            for subgroup in &group.groups {
                if let Some(e) = find_entry_by_uuid_internal(subgroup, name) {
                    return Some(e);
                }
            }

            return None;
        }

        for group in &self.groups {
            if let Some(e) = find_entry_by_uuid_internal(group, name) {
                return Some(e);
            }
        }

        return None;
    }

    pub fn search(&self, text: &str) -> Vec<Entry> {
        let re = regex::RegexBuilder::new(regex::escape(text).as_str())
            .case_insensitive(true)
            .build()
            .unwrap();
        fn entries_collect(re: &regex::Regex, group: &Group, entries: &mut Vec<Entry>) {
            for e in &group.entries {
                if re.is_match(e.title.as_str())
                    || re.is_match(e.user_name.as_str())
                    || re.is_match(e.notes.as_str())
                {
                    entries.push(e.clone());
                }
            }
            for g in &group.groups {
                entries_collect(re, g, entries);
            }
        }

        let mut entries = Vec::<Entry>::new();
        for g in &self.groups {
            entries_collect(&re, g, &mut entries);
        }
        return entries;
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<Entry> {
        fn entries_collect(group: &Group, entries: &mut Vec<Entry>) {
            for e in &group.entries {
                entries.push(e.clone());
            }
            for g in &group.groups {
                entries_collect(g, entries);
            }
        }

        let mut entries = Vec::<Entry>::new();
        for g in &self.groups {
            entries_collect(g, &mut entries);
        }
        return entries;
    }

    fn parse_group(element: &Element, random_stream: &mut ::streams::RandomStream) -> Group {
        let mut group = Group {
            uuid: String::new(),
            name: String::new(),
            notes: String::new(),
            groups: Vec::<Group>::new(),
            entries: Vec::<Entry>::new(),
        };
        for ref child in element_children(element) {
            if let Some(t) = text_child(child, "UUID") {
                group.uuid = t;
            } else if let Some(t) = text_child(child, "Name") {
                group.name = t;
            } else if let Some(t) = text_child(child, "Notes") {
                group.notes = t;
            } else if child.name().local_part() == "Group" {
                group
                    .groups
                    .push(Database::parse_group(child, random_stream));
            } else if child.name().local_part() == "Entry" {
                group
                    .entries
                    .push(Database::parse_entry(child, random_stream));
            }
        }
        return group;
    }

    fn parse_entry(element: &Element, random_stream: &mut ::streams::RandomStream) -> Entry {
        let mut entry = Entry {
            uuid: String::new(),
            notes: String::new(),
            password: Value::String(String::new()),
            title: String::new(),
            url: String::new(),
            user_name: String::new(),
        };
        for ref child in element_children(element) {
            if let Some(t) = text_child(child, "UUID") {
                entry.uuid = t;
            } else if child.name().local_part() == "String" {
                let mut name = String::new();
                let mut value = Value::String(String::new());
                for ref string_child in element_children(child) {
                    if let Some(t) = text_child(string_child, "Key") {
                        name = t;
                    }
                    if let Some(t) = text_child(string_child, "Value") {
                        value = Database::parse_value(string_child, t, random_stream);
                    }
                }
                match name.as_str() {
                    "Notes" => {
                        entry.notes = String::from(value);
                    }
                    "UserName" => {
                        entry.user_name = String::from(value);
                    }
                    "URL" => {
                        entry.url = String::from(value);
                    }
                    "Password" => {
                        entry.password = value;
                    }
                    "Title" => {
                        entry.title = String::from(value);
                    }
                    _ => {}
                }
            } else if child.name().local_part() == "History" {
                // Entry elements can themselves contain a history of previous states. The should
                // also be parsed so that any protected strings can be processed, so that the
                // random_stream can be in the right state for the other entries.
                for ref history_child in element_children(child) {
                    if history_child.name().local_part() == "Entry" {
                        Database::parse_entry(history_child, random_stream);
                    }
                }
            }
        }
        return entry;
    }

    fn parse_value(
        element: &Element,
        value: String,
        random_stream: &mut ::streams::RandomStream,
    ) -> Value {
        match element.attribute("Protected") {
            Some(protected) => {
                if protected.value() != "True" {
                    return Value::String(value);
                }
                let buf = base64::decode(value.as_str()).unwrap();
                let mut mask = vec![0u8; buf.len()];
                random_stream.process(mask.as_mut_slice());

                Value::ProtectedString(ProtectedString {
                    password: buf,
                    mask: mask,
                })
            }
            None => return Value::String(value),
        }
    }
}

#[cfg(test)]
mod test {
    use keys::Key;

    #[test]
    fn test_load_database() {
        let key = ::keys::CompositeKey::new(&[::keys::PasswordKey::new("password").key()]);
        let db = ::database::Database::open("./data/NewDatabase.kdbx", &key).unwrap();
        assert_eq!(
            db.entries(),
            vec![
                ::database::Entry {
                    uuid: String::from("bJClVAfg9E2jrCsPqH/NGg=="),
                    notes: String::from("Notes"),
                    password: ::database::Value::ProtectedString(::database::ProtectedString {
                        password: vec![56, 215, 38, 60, 118, 140, 233, 38],
                        mask: vec![104, 182, 85, 79, 1, 227, 155, 66],
                    }),
                    title: String::from("Sample Entry"),
                    url: String::from("http://www.somesite.com/"),
                    user_name: String::from("User Name"),
                },
                ::database::Entry {
                    uuid: String::from("v3Cs0nZmC0a+kUwFoxJyIg=="),
                    notes: String::from(""),
                    password: ::database::Value::ProtectedString(::database::ProtectedString {
                        password: vec![228, 235, 93, 165, 209],
                        mask: vec![213, 217, 110, 145, 228],
                    }),
                    title: String::from("Sample Entry #2"),
                    url: String::from("http://keepass.info/help/kb/kb090406_testform.html"),
                    user_name: String::from("Michael321"),
                },
                ::database::Entry {
                    uuid: String::from("RF0mxnljNUqXpQed8e3eXw=="),
                    notes: String::from("dflkdflkdlfkdlkf"),
                    password: ::database::Value::ProtectedString(::database::ProtectedString {
                        password: vec![
                            202, 211, 200, 247, 244, 220, 11, 27, 209, 182, 201, 44, 104, 222, 202,
                            33, 81, 147, 51, 161
                        ],
                        mask: vec![
                            250, 184, 251, 179, 134, 229, 89, 43, 180, 216, 191, 100, 33, 140, 164,
                            119, 21, 245, 127, 150
                        ],
                    }),
                    title: String::from("Foo"),
                    url: String::from(""),
                    user_name: String::from("bar"),
                },
                ::database::Entry {
                    uuid: String::from("yfhphRuv6keG+dEZI3RKuA=="),
                    notes: String::from(""),
                    password: ::database::Value::ProtectedString(::database::ProtectedString {
                        password: vec![
                            249, 176, 252, 99, 239, 101, 65, 20, 188, 99, 44, 156, 47, 44, 92, 3,
                            6, 248, 100, 3
                        ],
                        mask: vec![
                            178, 198, 189, 0, 215, 4, 115, 67, 228, 14, 84, 209, 67, 71, 18, 80,
                            113, 146, 21, 116
                        ],
                    }),
                    title: String::from("dfdlfk"),
                    url: String::from(""),
                    user_name: String::from("dflkdlfkdlf"),
                },
            ],
        );

        let entry = db.find_entry_by_uuid("bJClVAfg9E2jrCsPqH/NGg==").unwrap();
        assert_eq!(entry.title, String::from("Sample Entry"));
        let mut s = String::from(&entry.password);
        assert_eq!(s, String::from("Password"));

        ::database::ProtectedString::clear(&mut s);
        assert_eq!(s, String::from(""));

        assert_eq!(db.find_entry_by_uuid("inexistent"), None);
    }
}
