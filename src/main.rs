use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, Take},
    path::{Path, PathBuf}, process::Command,
};

use anyhow::Context;
use clap::Parser;
use zipunsplitlib::file::{JoinedFile, MemoryCowFile, Opener};

fn find_magic<R: Read>(mut reader: R, magic: &[u8]) -> anyhow::Result<Option<u64>> {
    use memchr::memmem::Finder;
    const BUF_SIZE: usize = 4096;
    assert!(magic.len() <= BUF_SIZE);
    let mut buffer = [0; BUF_SIZE]; // Buffer size of 4096 bytes
    let mut offset = 0;
    let overlap = magic.len() - 1;
    let mut n = overlap;

    let finder = Finder::new(magic);
    loop {
        let read = reader.read(&mut buffer[n..])?;
        if read == 0 {
            break;
        }

        n += read;
        if n < magic.len() {
            continue;
        }

        if let Some(pos) = finder.find(&buffer[..n]) {
            return Ok(Some(offset + pos as u64 - overlap as u64));
        }

        offset += n as u64 - overlap as u64;

        // Copy the last `overlap` bytes to the start of the buffer
        buffer.copy_within(n - overlap..n, 0);
        n = overlap;
    }

    Ok(None)
}

#[derive(Debug)]
pub struct SetupEntry {
    pub name: String,
    pub size: i32,
    pub checksum: i32,
    pub offset: u64,
}

pub struct Setup<R> {
    reader: R,
    nfo_offset: u64,
}

impl<R: Read + Seek> Setup<R> {
    pub fn new(mut reader: R) -> anyhow::Result<Self> {
        let nfo_offset = find_magic(&mut reader, b"NFO300")?.context("NFO300 not found")?;
        Ok(Self { reader, nfo_offset })
    }

    pub fn entries(&mut self) -> anyhow::Result<Vec<SetupEntry>>
    where
        R: BufRead,
    {
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
            entries.push(SetupEntry {
                name: name.trim_matches('"').to_string(),
                size: size.trim_matches('"').parse::<i32>()?,
                checksum: checksum.trim_matches('"').parse::<i32>()?,
                offset: 0,
            });
        }

        let mut data_offset = self.reader.seek(std::io::SeekFrom::Current(0))?;
        for entry in &mut entries {
            entry.offset = data_offset;
            data_offset += entry.size as u64;
        }

        Ok(entries)
    }

    pub fn entry_reader(&mut self, entry: &SetupEntry) -> anyhow::Result<BufReader<Take<&mut R>>> {
        self.reader.seek(std::io::SeekFrom::Start(entry.offset))?;
        Ok(BufReader::new(self.reader.by_ref().take(entry.size as u64)))
    }

    pub fn extract_entries_to(
        &mut self,
        entries: &[SetupEntry],
        out_dir: &Path,
    ) -> anyhow::Result<Vec<PathBuf>> {
        let mut paths = vec![];
        for entry in entries {
            let mut reader = self.entry_reader(entry)?;

            // Ensure the path name contains only letters, digits and dots
            let name = entry
                .name
                .replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_");
            let out_path = out_dir.join(&name);
            let mut out = BufWriter::new(File::create(&out_path)?);
            io::copy(&mut reader, &mut out)?;

            paths.push(out_path);
        }

        Ok(paths)
    }
}

pub struct JoinedOpener(pub Vec<PathBuf>);

impl Opener for JoinedOpener {
    fn open_split(&mut self, index: usize) -> io::Result<File> {
        Ok(File::open(&self.0[index])?)
    }

    fn num_splits(&self) -> usize {
        self.0.len()
    }
}

fn extract_zip_split(paths: Vec<PathBuf>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let joined_file = JoinedFile::new(JoinedOpener(paths))?;
    let split_ranges = joined_file.splits();
    let mut cow_file = MemoryCowFile::new(joined_file, 4096)?;
    zipunsplitlib::split::fix_offsets(&mut cow_file, &split_ranges).context("Fix offsets")?;
    cow_file.rewind()?;

    let mut archive = zip::ZipArchive::new(cow_file)?;
    //TODO create HShield directory
    archive.extract(setup_dir)?;

    Ok(())
}

fn extract_cab_split(paths: Vec<PathBuf>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    // Use cabextract
    //TODO maybe use 
    Command::new("cabextract")
        .args(&["-d", setup_dir.as_ref().to_str().unwrap()])
        .args(paths.iter().map(|p| p.to_str().unwrap()))
        .output()?;

    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The setup file to extract
    #[arg(short, long)]
    setup: String,

    /// The setup directory
    #[arg(short, long, default_value = "setup")]
    dir: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let r = BufReader::new(std::fs::File::open(args.setup)?);
    let mut setup = Setup::new(r)?;

    // Extract all entries to a temporary directory
    let entries = setup.entries()?;
    let tmp_dir = std::env::temp_dir().join("mssetupx");
    std::fs::remove_dir_all(&tmp_dir).ok();
    std::fs::create_dir(&tmp_dir).context("Tmp dir")?;
    let out = setup.extract_entries_to(&entries, &tmp_dir)?;

    let is_zip = out.iter().any(|p| p.extension().unwrap() == "zip");
    if is_zip {
        extract_zip_split(out, args.dir)?;
    } else {
        extract_cab_split(out, args.dir)?;
    }

    std::fs::remove_dir_all(&tmp_dir)?;

    Ok(())
}
