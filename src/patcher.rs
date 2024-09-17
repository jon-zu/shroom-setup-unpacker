use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Take, Write},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::patch::{wz_patch_verify_crc, WzPatchFilePath, WzPatchHandler, WZ_PATCHER_CRC};

pub const PATCH_BUFFER_SIZE: usize = 4096;

pub struct OldFile<R> {
    pub rdr: R,
}

impl<R: Read + Seek> OldFile<R> {
    pub fn new(rdr: R) -> Self {
        OldFile { rdr }
    }

    pub fn verify_checksum(&mut self, checksum: u32) -> anyhow::Result<()> {
        self.rdr.seek(SeekFrom::Start(0))?;
        wz_patch_verify_crc(&mut self.rdr, checksum)?;
        Ok(())
    }

    pub fn block_reader(&mut self, offset: u32, len: u32) -> anyhow::Result<Take<&mut R>> {
        self.rdr.seek(SeekFrom::Start(offset as u64))?;
        Ok(self.rdr.by_ref().take(len as u64))
    }
}

pub struct NewFile<W> {
    pub wrtr: W,
    pub digest: crc::Digest<'static, u32>,
}

impl<W: Write> NewFile<W> {
    pub fn new(wrtr: W) -> Self {
        NewFile {
            wrtr,
            digest: WZ_PATCHER_CRC.digest(),
        }
    }

    fn write_from(&mut self, rdr: &mut impl Read) -> io::Result<()> {
        let mut buf = [0u8; PATCH_BUFFER_SIZE];
        loop {
            let n = rdr.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.wrtr.write_all(&buf[..n])?;
            self.digest.update(&buf[..n]);
        }
        Ok(())
    }

    pub fn write_repeat(&mut self, b: u8, len: usize) -> anyhow::Result<()> {
        self.write_from(&mut io::repeat(b).take(len as u64))?;
        Ok(())
    }

    pub fn checksum(&mut self) -> u32 {
        self.digest.clone().finalize()
    }
}

struct CurrentPatchFile {
    old_file: OldFile<File>,
    new_file: NewFile<File>,
    path: WzPatchFilePath,
}

pub struct WzPatcher {
    dir: PathBuf,
    current: Option<CurrentPatchFile>,
}

impl WzPatcher {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        WzPatcher {
            dir: dir.as_ref().to_path_buf(),
            current: None,
        }
    }

    fn get_current_mut(&mut self) -> anyhow::Result<&mut CurrentPatchFile> {
        self.current
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No patch file open"))
    }

    fn clear_current(&mut self) {
        self.current = None;
    }

    fn resolve_old(&self, p: &WzPatchFilePath) -> PathBuf {
        self.dir.join(&p.0)
    }

    fn resolve_new(&self, p: &WzPatchFilePath) -> PathBuf {
        let _ = std::fs::create_dir(self.dir.join("out"));
        self.dir.join("out").join(&p.0)
    }

    fn new_file(&self, p: &WzPatchFilePath) -> anyhow::Result<NewFile<File>> {
        Ok(NewFile::new(File::create(self.resolve_new(p))?))
    }

    fn set_current(&mut self, path: &WzPatchFilePath, checksum: u32) -> anyhow::Result<()> {
        let old = self.resolve_old(path);
        let new = self.resolve_new(path);

        let mut old_file = OldFile::new(File::open(&old)?);
        old_file.verify_checksum(checksum)?;

        let new_file = NewFile::new(File::create(&new)?);
        self.current = Some(CurrentPatchFile {
            old_file,
            new_file,
            path: path.clone(),
        });
        Ok(())
    }
}

impl WzPatchHandler for WzPatcher {
    fn handle_add<R: Read>(
        &mut self,
        p: &WzPatchFilePath,
        data: &mut crate::patch::WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.new_file(p)?.write_from(data)?;

        Ok(())
    }

    fn handle_remove(&mut self, p: &WzPatchFilePath) -> anyhow::Result<()> {
        let p = self.resolve_old(p);
        std::fs::remove_file(p)?;

        Ok(())
    }

    fn handle_modify(
        &mut self,
        p: &WzPatchFilePath,
        old_checksum: u32,
        _new_checksum: u32,
    ) -> anyhow::Result<()> {
        self.set_current(p, old_checksum)?;
        Ok(())
    }

    fn handle_mod_repeat(&mut self, byte: u8, len: u32) -> anyhow::Result<()> {
        let cur = self.get_current_mut()?;
        cur.new_file.write_repeat(byte, len as usize)?;
        Ok(())
    }

    fn handle_mod_new_block<R: Read>(
        &mut self,
        data: &mut crate::patch::WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.get_current_mut()?.new_file.write_from(data)?;
        Ok(())
    }

    fn handle_mod_old_block(&mut self, offset: u32, len: u32) -> anyhow::Result<()> {
        let cur = self.get_current_mut()?;
        let mut rdr = cur.old_file.block_reader(offset, len)?;
        cur.new_file.write_from(&mut rdr)?;
        Ok(())
    }

    fn handle_mod_end(&mut self, checksum: u32) -> anyhow::Result<()> {
        let cur = self.get_current_mut()?;
        let actual = cur.new_file.checksum();
        if actual != checksum {
            anyhow::bail!(
                "Checksum mismatch: expected 0x{:08x}, got 0x{:08x}",
                checksum,
                actual
            );
        }
        self.clear_current();
        Ok(())
    }
}

#[derive(Debug, Default, Serialize)]
pub struct WzPatcherInfo {
    pub added_files: Vec<(String, usize)>,
    pub removed_files: Vec<String>,
    pub modified_files: Vec<(String, usize)>,
}

impl WzPatchHandler for WzPatcherInfo {
    fn handle_add<R: Read>(
        &mut self,
        p: &WzPatchFilePath,
        data: &mut crate::patch::WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.added_files.push((p.0.clone(), data.len() as usize));
        Ok(())
    }

    fn handle_remove(&mut self, p: &WzPatchFilePath) -> anyhow::Result<()> {
        self.removed_files.push(p.0.clone());
        Ok(())
    }

    fn handle_modify(
        &mut self,
        p: &WzPatchFilePath,
        _old_checksum: u32,
        _new_checksum: u32,
    ) -> anyhow::Result<()> {
        self.modified_files.push((p.0.clone(), 0));
        Ok(())
    }

    fn handle_mod_repeat(&mut self, _byte: u8, _len: u32) -> anyhow::Result<()> {
        self.modified_files.last_mut().unwrap().1 += _len as usize;
        Ok(())
    }

    fn handle_mod_new_block<R: Read>(
        &mut self,
        data: &mut crate::patch::WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.modified_files.last_mut().unwrap().1 += data.len() as usize;
        Ok(())
    }

    fn handle_mod_old_block(&mut self, _offset: u32, len: u32) -> anyhow::Result<()> {
        self.modified_files.last_mut().unwrap().1 += len as usize;
        Ok(())
    }

    fn handle_mod_end(&mut self, _checksum: u32) -> anyhow::Result<()> {
        Ok(())
    }
}
