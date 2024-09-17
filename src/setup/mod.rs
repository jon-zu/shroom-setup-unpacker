use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::util::find_needle;

pub mod nfo300;
pub mod is;
pub mod nsis;


pub trait Entry {
    fn name(&self) -> &str;
    fn size(&self) -> u64;
}

pub trait Setup {
    type Entry: Entry;
    type EntryReader<'a>: std::io::Read where Self: 'a;

    fn tag() -> &'static [u8];
    fn entries(&mut self) -> anyhow::Result<Vec<Self::Entry>>;
    fn entry_reader(&mut self, entry: &Self::Entry) -> anyhow::Result<Self::EntryReader<'_>>;

    fn size(&self) -> u64;

    fn find_tag(mut reader: impl std::io::Read + std::io::Seek) -> anyhow::Result<Option<u64>> {
        let tag = Self::tag();
        let offset = find_needle(&mut reader, tag)?;
        Ok(offset)
    }


    fn extract_to(&mut self, out_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in self.entries()? {
            let mut reader = self.entry_reader(&entry)?;
            let name = entry
                .name()
                .replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_");
            let out_path = out_dir.join(name);
            let mut writer = std::fs::File::create(&out_path)
                .with_context(|| format!("Failed to create file: {:?}", out_path))?;
            std::io::copy(&mut reader, &mut writer)
                .with_context(|| format!("Failed to write to file: {:?}", out_path))?;
            files.push(out_path);
        }
        Ok(files)
    }
}

impl<'a, T: Setup> Setup for &'a mut T {
    type Entry = T::Entry;

    type EntryReader<'b> = T::EntryReader<'b> where Self: 'b;

    fn tag() -> &'static [u8] {
        T::tag()
    }

    fn entries(&mut self) -> anyhow::Result<Vec<Self::Entry>> {
        (**self).entries()
    }

    fn entry_reader(&mut self, entry: &Self::Entry) -> anyhow::Result<Self::EntryReader<'_>> {
        (**self).entry_reader(entry)
    }

    fn size(&self) -> u64 {
        (**self).size()
    }
}