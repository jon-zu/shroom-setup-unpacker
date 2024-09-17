use std::{collections::VecDeque, io::{Read, Seek, SeekFrom}, path::{Path, PathBuf}};

pub const MAX_PE_SIZE: u64 = 40 * 1024 * 1024;

pub fn find_needle<R: Read>(mut reader: R, needle: &[u8]) -> anyhow::Result<Option<u64>> {
    use memchr::memmem::Finder;
    const BUF_SIZE: usize = 4096;
    assert!(needle.len() <= BUF_SIZE);
    let mut buffer = [0; BUF_SIZE]; // Buffer size of 4096 bytes
    let mut offset = 0;
    let overlap = needle.len() - 1;
    let mut n = overlap;

    let finder = Finder::new(needle);
    loop {
        let read = reader.read(&mut buffer[n..])?;
        if read == 0 {
            break;
        }

        n += read;
        if n < needle.len() {
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

pub fn find_padding_data<R: Read + Seek>(
    mut reader: R,
    offset: u64,
    limit: u64,
) -> anyhow::Result<Option<u64>> {
    const PAT: &[u8] = b"PADDINGXXPADDING";
    let pad_ix = find_needle(reader.by_ref().take(limit), PAT)?;
    let Some(pad_ix) = pad_ix else {
        return Ok(None);
    };
    let pad_ix = offset + pad_ix;
    reader.seek(SeekFrom::Start(pad_ix))?;
    let mut buf = [0u8; 4096];
    reader.read_exact(&mut buf)?;


    for (i, chunk) in buf.chunks(16).enumerate() {
        if chunk != PAT {
            let strip = chunk
                .iter()
                .zip(PAT.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0) as u64;
            return Ok(Some(pad_ix + i as u64 * 16 + strip));
        }
    }

    Ok(None)
}

pub enum SetupFormat {
    InstallShield(u64),
    NFO300(u64),
}

impl SetupFormat {
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> anyhow::Result<Self> {
        let mut offset = 0;
        loop {
            reader.seek(SeekFrom::Start(offset))?;
            let ix = find_padding_data(reader.by_ref(), offset, MAX_PE_SIZE - offset)?;
            let Some(ix) = ix else {
                anyhow::bail!("Could not find padding data");
            };

            reader.seek(SeekFrom::Start(ix))?;
            let mut magic = [0u8; 16];
            reader.read_exact(&mut magic)?;

            if magic.starts_with(b"NFO300") {
                break Ok(Self::NFO300(ix));
            } else if magic.starts_with(b"InstallShield") {
                break Ok(Self::InstallShield(ix));
            } else {
                offset = ix + 16;
            }
        }
    }
}


pub fn get_all_nested_files(dir: impl AsRef<Path>) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries = vec![];
    let mut q = VecDeque::new();
    q.push_back(dir.as_ref().to_path_buf());
    while let Some(d) = q.pop_front() {
        for entry in std::fs::read_dir(d)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                q.push_back(path);
            } else {
                entries.push(path);
            }
        }
    }

    Ok(entries)
}