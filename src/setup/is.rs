use std::{ffi::CStr, io::{Read, Seek, SeekFrom}};

use anyhow::Context;
use bytemuck::{Pod, Zeroable};

use crate::{
    setup::Setup,
    util::find_needle,
};

use super::Entry;

#[derive(Debug, Pod, Clone, Copy, Zeroable)]
#[repr(C, packed)]
pub struct IsHeader {
    pub signature: [u8; 14],
    pub num_files: u16,
    pub ty: u32,
    pub x4: [u8; 8],
    pub x5: u16,
    pub x6: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct FilePath(pub [u8; 260]);

impl std::fmt::Debug for FilePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = std::ffi::CStr::from_bytes_until_nul(&self.0).unwrap();
        write!(f, "{}", path.to_str().unwrap())
    }
}

impl std::fmt::Display for FilePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = std::ffi::CStr::from_bytes_until_nul(&self.0).unwrap();
        write!(f, "{}", path.to_str().unwrap())
    }
}

unsafe impl bytemuck::Zeroable for FilePath {
    fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

unsafe impl bytemuck::Pod for FilePath {}

#[derive(Debug, Pod, Clone, Copy, Zeroable)]
#[repr(C, packed)]
pub struct IsFileAttributes {
    pub file_name: FilePath,
    pub encoded_flags: u32,
    pub x3: u32,
    pub file_len: u32,
    pub x5: [u8; 8],
    pub is_unicode_launcher: u16,
    pub x7: [u8; 30],
}

#[derive(Debug, Pod, Clone, Copy, Zeroable)]
#[repr(C, packed)]
pub struct IsFileAttributesX {
    pub filename_len: u32,
    pub encoded_flags: u32,
    pub x3: [u8; 2],
    pub file_len: u32,
    pub x5: [u8; 8],
    pub is_unicode_launcher: u16,
}

#[derive(Debug)]
pub struct IsSetup<R> {
    hdr: IsHeader,
    hdr_offset: u64,
    rdr: R,
    size: u64
}

#[derive(Debug)]
pub struct IsEntry {
    attr: IsFileAttributes,
    offset: u64,
}

impl Entry for IsEntry {
    fn name(&self) -> &str {
        let cname = CStr::from_bytes_until_nul(&self.attr.file_name.0[..]).expect("Invalid filename");
        cname.to_str().expect("Invalid filename")
    }

    fn size(&self) -> u64 {
        self.attr.file_len as u64
    }
}

fn gen_key(key: &mut [u8]) {
    const MAGIC: [u8; 4] = [0x13, 0x35, 0x86, 0x07];

    for (i, k) in key.iter_mut().enumerate() {
        *k ^= MAGIC[i % 4];
    }
}

fn decode_byte(b: u8, k: u8) -> u8 {
    !(k ^ b.rotate_right(4))
}

/*fn encode_byte(b: u8, k: u8) -> u8 {
    let b = !b ^ k;
    b.rotate_left(4)
}*/

fn decode_data(data: &mut [u8], key: &[u8], offset: u32) {
    for (i, b) in data.iter_mut().enumerate() {
        *b = decode_byte(*b, key[(i + offset as usize) % key.len()]);
    }
}

#[derive(Debug)]
pub struct EntryReader<'a, R> {
    reader: std::io::Take<&'a mut R>,
    key: Vec<u8>,
    offset: u64,
}

impl<'a, R: Read> Read for EntryReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buf)?;
        if read == 0 {
            return Ok(0);
        }

        let dec_offset = self.offset % 1024;
        self.offset += read as u64;

        for block in 0..(read / 1024) {
            let start = block * 1024;
            decode_data(&mut buf[start..start + 1024], &self.key, dec_offset as u32);
        }

        let rem = read % 1024;
        if rem > 0 {
            let start = read - rem;
            decode_data(&mut buf[start..read], &self.key, dec_offset as u32);
        }

        Ok(read)
    }
}

impl<R: Read + Seek> IsSetup<R> {
    pub fn new(mut rdr: R, hdr_offset: u64) -> anyhow::Result<Self> {
        let size = rdr.seek(SeekFrom::End(0))?;
        rdr.seek(SeekFrom::Start(hdr_offset))?;
        let mut hdr = IsHeader::zeroed();
        rdr.read_exact(bytemuck::bytes_of_mut(&mut hdr))?;

        if hdr.signature != *b"InstallShield\0" {
            anyhow::bail!("Invalid InstallShield header: {:?}", hdr.signature);
        }

        Ok(Self {
            hdr,
            hdr_offset,
            rdr,
            size
        })
    }

    pub fn new_detect(mut rdr: R) -> anyhow::Result<Self> {
        rdr.seek(std::io::SeekFrom::Start(0))?;
        let offset = find_needle(rdr.by_ref(), Self::tag())?.context("No InstallShield tag found")?;
        Self::new(
            rdr,
            offset
        )
    }
}

impl<R: Read + Seek> Setup for IsSetup<R> {
    type Entry = IsEntry;
    type EntryReader<'a> = EntryReader<'a, R> where R: 'a;

    fn tag() -> &'static [u8] {
        b"InstallShield"
    }

    fn entries(&mut self) -> anyhow::Result<Vec<Self::Entry>> {
        let mut files = Vec::new();
        let mut offset = self.hdr_offset + std::mem::size_of::<IsHeader>() as u64;
        self.rdr.seek(SeekFrom::Start(offset))?;

        for _ in 0..self.hdr.num_files {
            let mut attr = IsFileAttributes::zeroed();
            self.rdr.read_exact(bytemuck::bytes_of_mut(&mut attr))?;
            let len = attr.file_len as u64;
            files.push(IsEntry { attr, offset });
            offset = self.rdr.seek(SeekFrom::Current(len as i64))?;
        }

        Ok(files)
    }

    fn entry_reader(&mut self, entry: &Self::Entry) -> anyhow::Result<Self::EntryReader<'_>> {
        let offset = entry.offset + std::mem::size_of::<IsFileAttributes>() as u64;
        self.rdr.seek(SeekFrom::Start(offset))?;

        // Filename is the key
        let len = entry.attr.file_name.0.iter().position(|&b| b == 0).unwrap();
        let mut key = entry.attr.file_name.0[..len].to_vec();
        gen_key(&mut key);

        Ok(EntryReader {
            reader: self.rdr.by_ref().take(entry.attr.file_len as u64),
            key,
            offset: 0,
        })
    }
    
    fn size(&self) -> u64 {
        self.size - self.hdr_offset
    }
}
