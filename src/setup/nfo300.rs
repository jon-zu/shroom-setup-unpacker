use std::io::{BufRead, Read, Seek, Take};

use anyhow::Context;

use crate::util::{find_needle, MAX_PE_SIZE};

use super::{Entry, Setup};

#[derive(Debug)]
pub struct Nfo300Entry {
    pub name: String,
    pub size: i32,
    pub checksum: i32,
    pub offset: u64,
}

impl Entry for Nfo300Entry {
    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size as u64
    }
}

#[derive(Debug)]
pub struct EntryReader<'a, R> {
    reader: Take<&'a mut R>,
}

impl<'a, R: Read> Read for EntryReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

#[derive(Debug)]
pub struct Nfo300Setup<R> {
    reader: R,
    nfo_offset: u64,
    size: u64,
}

impl<R: Read + Seek> Nfo300Setup<R> {
    pub fn new(mut rdr: R, offset: u64) -> anyhow::Result<Self> {
        let size = rdr.seek(std::io::SeekFrom::End(0))?;
        
        Ok(Self {
            reader: rdr,
            nfo_offset: offset,
            size,
        })
    }

    pub fn new_detect(mut rdr: R) -> anyhow::Result<Self> where R: BufRead {
        //let offset = find_padding_data(rdr.by_ref(), MAX_PE_SIZE)?.context("No padding data found")?;
        rdr.seek(std::io::SeekFrom::Start(0))?;
        let offset = find_needle(rdr.by_ref().take(MAX_PE_SIZE), Self::tag())?.context("No NFO300 tag found")?;
        Self::new(
            rdr,
            offset
        )
    }
}

impl<R: BufRead + Read + Seek> Setup for Nfo300Setup<R> {
    type Entry = Nfo300Entry;
    type EntryReader<'a> = EntryReader<'a, R> where R: 'a;

    fn entries(&mut self) -> anyhow::Result<Vec<Self::Entry>> {
        self.reader
            .seek(std::io::SeekFrom::Start(self.nfo_offset))?;
        let mut entries = vec![];
        let mut line = String::new();

        let mut limited = self.reader.by_ref().take(1000);

        // Skip nfo line
        limited.read_line(&mut line)?;

        // Read as long as the line starts with a quote
        while limited.fill_buf()?[0] == b'"' {
            line.clear();
            limited.read_line(&mut line)?;

            let line = line.trim();
            let (name, rest) = line.split_once(',').context("Invalid entry name")?;
            let (checksum, size) = rest.split_once(',').context("Invalid entry size")?;
            entries.push(Nfo300Entry {
                name: name.trim_matches('"').to_string(),
                size: size.trim_matches('"').parse::<i32>()?,
                checksum: checksum.trim_matches('"').parse::<i32>()?,
                offset: 0,
            });
        }

        let mut data_offset = self.reader.stream_position()?;
        for entry in &mut entries {
            entry.offset = data_offset;
            data_offset += entry.size as u64;
        }

        Ok(entries)
    }

    fn entry_reader(&mut self, entry: &Self::Entry) -> anyhow::Result<Self::EntryReader<'_>> {
        self.reader.seek(std::io::SeekFrom::Start(entry.offset))?;
        let size = u32::from_le_bytes(entry.size.to_le_bytes());
        Ok(EntryReader {
            reader: self.reader.by_ref().take(size as u64),
        })
    }

    fn size(&self) -> u64 {
        self.size - self.nfo_offset
    }
    
    fn tag() -> &'static [u8] {
        b"NFO300"
    }
}
