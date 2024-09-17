use std::{fs::File, io::{self, BufRead, BufReader, Read, Seek}, path::Path};

use binrw::{io::NoSeek, BinRead};
use flate2::bufread::ZlibDecoder;
use serde::Serialize;

pub const CRC_32_PATCHER: crc::Algorithm<u32> = crc::Algorithm {
    width: 32,
    poly: 0x04c11db7,
    init: 0,
    refin: false,
    refout: false,
    xorout: 0x00000000,
    check: 0xCE94872,
    residue: 0x00000000,
};
pub const WZ_PATCHER_CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&CRC_32_PATCHER);

pub fn wz_patch_calc_crc(mut r: impl Read) -> io::Result<u32> {
    let mut digest = WZ_PATCHER_CRC.digest();
    let mut buf = [0u8; 4096];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(digest.finalize())
}

pub fn wz_patch_verify_crc(mut r: impl Read, expected: u32) -> io::Result<()> {
    let checksum = wz_patch_calc_crc(&mut r)?;
    if checksum != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Checksum mismatch expected {}, got {}", expected, checksum),
        ));
    }
    Ok(())
}

#[derive(BinRead, Serialize, Debug)]
#[br(little, magic = b"WzPatch\x1A")]
pub struct WzPatchHdr {
    pub version: i32,
    pub checksum: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct WzPatchFilePath(pub String);

impl WzPatchFilePath {
    pub fn read(r: &mut impl Read) -> std::io::Result<(Self, u8)> {
        //TODO maybe make this more efficient
        // This reads a string until either 0,1,2 is hit
        let mut name = String::new();
        let mut b = [0u8; 1];
        loop {
            r.read_exact(&mut b)?;
            if matches!(b[0], 0 | 1 | 2) {
                break;
            }
            name.push(b[0] as char);
        }

        Ok((Self(name), b[0]))
    }
}

#[derive(Debug, Serialize)]
pub enum WzPatchOp {
    AddFile {
        len: u32,
        checksum: u32,
    },
    RemoveFile,
    ModifyFile {
        old_checksum: u32,
        new_checksum: u32,
    },
}

#[derive(Debug, Serialize)]
pub struct WzPatchFile {
    pub file: WzPatchFilePath,
    pub op: WzPatchOp,
}

impl BinRead for WzPatchFile {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let (path, op) = WzPatchFilePath::read(reader)?;
        let op = match op {
            0 => WzPatchOp::AddFile {
                len: u32::read_options(reader, endian, ())?,
                checksum: u32::read_options(reader, endian, ())?,
            },
            1 => WzPatchOp::ModifyFile {
                old_checksum: u32::read_options(reader, endian, ())?,
                new_checksum: u32::read_options(reader, endian, ())?,
            },
            2 => WzPatchOp::RemoveFile,
            _ => {
                return Err(binrw::Error::NoVariantMatch {
                    pos: reader.stream_position()?,
                })
            }
        };

        Ok(Self { file: path, op })
    }
}

#[derive(Debug, Serialize)]
pub enum WzPatchBlock {
    /// Repeat a byte `byte` `len` times
    Repeat { byte: u8, len: u32 },
    /// New block with `len` bytes, following for this block
    NewBlock { len: u32 },
    /// Copy `len` bytes from the old file at `offset`
    OldBlock { len: u32, offset: u32 },
    /// End of the block
    End,
}

impl WzPatchBlock {
    pub fn out_len(&self) -> u32 {
        match self {
            Self::Repeat { len, .. } => *len,
            Self::NewBlock { len } => *len,
            Self::OldBlock { len, .. } => *len,
            Self::End => 0,
        }
    }

    pub fn in_len(&self) -> u32 {
        match self {
            Self::NewBlock { len, .. } => *len,
            _ => 0,
        }
    }
}

impl BinRead for WzPatchBlock {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let value = u32::read_options(reader, endian, ())?;
        Ok(match value >> 28 {
            0x8 => Self::NewBlock {
                len: value & 0xFFFFFFF,
            },
            0xC => Self::Repeat {
                byte: (value & 0xff) as u8,
                len: (value >> 8) & 0xFFFFF,
            },
            _ if value == 0 => Self::End,
            _ => Self::OldBlock {
                len: value & 0xFFFFFFF,
                offset: u32::read_options(reader, endian, ())?,
            },
        })
    }
}

#[derive(Debug)]
pub struct WzPatch<R> {
    rdr: R,
    hdr: WzPatchHdr,
    data_offset: u64,
}

impl WzPatch<BufReader<File>> {
    pub fn open(p: impl AsRef<Path>) -> anyhow::Result<Self> {
        let file = std::fs::File::open(p)?;
        let rdr = BufReader::new(file);
        Self::new(rdr)
    }

}

impl<R: BufRead + Read + Seek> WzPatch<R> {
    pub fn new(mut rdr: R) -> anyhow::Result<Self> {
        let hdr = WzPatchHdr::read_le(&mut rdr)?;
        let data_offset = rdr.stream_position()?;
        Ok(Self {
            rdr,
            hdr,
            data_offset,
        })
    }

    pub fn version(&self) -> i32 {
        self.hdr.version
    }

    pub fn verify_checksum(&mut self) -> anyhow::Result<()> {
        self.rdr.seek(std::io::SeekFrom::Start(self.data_offset))?;
        wz_patch_verify_crc(&mut self.rdr, self.hdr.checksum)?;
        Ok(())
    }

    pub fn patch_stream(&mut self) -> anyhow::Result<WzPatchStream<NoSeek<ZlibDecoder<&mut R>>>> {
        self.rdr.seek(std::io::SeekFrom::Start(self.data_offset))?;
        let deflate = flate2::bufread::ZlibDecoder::new(&mut self.rdr);
        Ok(WzPatchStream {
            rdr: NoSeek::new(deflate),
        })
    }

    pub fn process(&mut self, handler: &mut impl WzPatchHandler) -> anyhow::Result<()> {
        let stream = self.patch_stream()?;
        stream.process(handler)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct WzPatchStream<R> {
    rdr: R,
}

#[derive(Debug)]
pub struct WzPatchDataStream<R> {
    rdr: R,
    len: u32,
    checksum: u32,
}

impl<R: Read> Read for WzPatchDataStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rdr.read(buf)
    }
}

impl<R: Read> WzPatchDataStream<R> {
    pub fn new(rdr: R, len: u32, checksum: u32) -> Self {
        Self { rdr, len, checksum }
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn clear(&mut self) -> io::Result<()> {
        io::copy(&mut self.rdr, &mut io::empty())?;
        Ok(())
    }
}

pub trait WzPatchHandler {
    fn handle_add<R: Read>(
        &mut self,
        p: &WzPatchFilePath,
        data: &mut WzPatchDataStream<R>,
    ) -> anyhow::Result<()>;
    fn handle_remove(&mut self, p: &WzPatchFilePath) -> anyhow::Result<()>;
    fn handle_modify(
        &mut self,
        p: &WzPatchFilePath,
        old_checksum: u32,
        new_checksum: u32,
    ) -> anyhow::Result<()>;

    fn handle_mod_repeat(&mut self, byte: u8, len: u32) -> anyhow::Result<()>;
    fn handle_mod_new_block<R: Read>(
        &mut self,
        data: &mut WzPatchDataStream<R>,
    ) -> anyhow::Result<()>;
    fn handle_mod_old_block(&mut self, offset: u32, len: u32) -> anyhow::Result<()>;
    fn handle_mod_end(&mut self, checksum: u32) -> anyhow::Result<()>;
}

impl<R: Read> Read for WzPatchStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.rdr.read(buf)
    }
}

impl<R: Read + Seek> WzPatchStream<R> {
    pub fn process(mut self, handler: &mut impl WzPatchHandler) -> anyhow::Result<()> {
        loop {
            let file = match WzPatchFile::read_le(&mut self.rdr) {
                Ok(file) => file,
                //TODO handle only eof
                Err(_e) => {
                    break;
                }
            };
            match file.op {
                WzPatchOp::AddFile { len, checksum } => {
                    let mut data =
                        WzPatchDataStream::new(self.rdr.by_ref().take(len as u64), len, checksum);
                    handler.handle_add(&file.file, &mut data)?;
                    data.clear()?;
                }
                WzPatchOp::RemoveFile => {
                    handler.handle_remove(&file.file)?;
                }
                WzPatchOp::ModifyFile {
                    old_checksum,
                    new_checksum,
                } => {
                    handler.handle_modify(&file.file, old_checksum, new_checksum)?;
                    self.process_blocks(handler)?;
                    handler.handle_mod_end(new_checksum)?;
                }
            }
        }

        Ok(())
    }

    fn process_blocks(&mut self, handler: &mut impl WzPatchHandler) -> anyhow::Result<()> {
        loop {
            let block = WzPatchBlock::read_le(&mut self.rdr)?;
            match block {
                WzPatchBlock::End => break Ok(()),
                WzPatchBlock::NewBlock { len } => {
                    let mut data =
                        WzPatchDataStream::new(self.rdr.by_ref().take(len as u64), len, 0);
                    handler.handle_mod_new_block(&mut data)?;
                    data.clear()?;
                }
                WzPatchBlock::OldBlock { len, offset } => {
                    handler.handle_mod_old_block(offset, len)?;
                }
                WzPatchBlock::Repeat { byte, len } => {
                    handler.handle_mod_repeat(byte, len)?;
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct TextHandler {
    pub w: String,
    pub cur_file: Option<String>,
}

impl WzPatchHandler for TextHandler {
    fn handle_add<R: Read>(
        &mut self,
        p: &WzPatchFilePath,
        data: &mut WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.w
            .push_str(&format!("Add: {} len: {}\n", p.0, data.len()));
        Ok(())
    }

    fn handle_remove(&mut self, p: &WzPatchFilePath) -> anyhow::Result<()> {
        self.w.push_str(&format!("Remove: {}\n", p.0));
        Ok(())
    }

    fn handle_modify(
        &mut self,
        p: &WzPatchFilePath,
        old_checksum: u32,
        new_checksum: u32,
    ) -> anyhow::Result<()> {
        self.w.push_str(&format!(
            "Modify: {} old: {} new: {}\n",
            p.0, old_checksum, new_checksum
        ));
        self.cur_file = Some(p.0.clone());
        Ok(())
    }

    fn handle_mod_repeat(&mut self, byte: u8, len: u32) -> anyhow::Result<()> {
        self.w.push_str(&format!(
            "\t {} - Repeat: {} len: {}\n",
            self.cur_file.as_ref().unwrap(),
            byte,
            len
        ));
        Ok(())
    }

    fn handle_mod_new_block<R: Read>(
        &mut self,
        data: &mut WzPatchDataStream<R>,
    ) -> anyhow::Result<()> {
        self.w.push_str(&format!(
            "\t {} - New Block {}\n",
            self.cur_file.as_ref().unwrap(),
            data.len()
        ));
        Ok(())
    }

    fn handle_mod_old_block(&mut self, offset: u32, len: u32) -> anyhow::Result<()> {
        self.w.push_str(&format!(
            "\t {} - Old Block offset: {} len: {}\n",
            self.cur_file.as_ref().unwrap(),
            offset,
            len
        ));
        Ok(())
    }

    fn handle_mod_end(&mut self, checksum: u32) -> anyhow::Result<()> {
        self.w
            .push_str(&format!("\t {} - End {checksum}\n", self.cur_file.as_ref().unwrap()));
        self.cur_file = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use crate::patcher::{WzPatcher, WzPatcherInfo};

    use super::*;

    #[test]
    fn patch() {
        let patch_file = "/home/jonas/Downloads/00083to00084.patch";
        let file = BufReader::new(std::fs::File::open(patch_file).unwrap());

        let mut patch = WzPatch::new(file).unwrap();
        patch.verify_checksum().unwrap();
        //dbg!(&patch);
        todo!();

        let mut handler = TextHandler::default();
        let stream = patch.patch_stream().unwrap();
        stream.process(&mut handler).unwrap();

        std::fs::write("patch.txt", handler.w).unwrap();
        todo!();

        //patch.mods().unwrap();
    }

    #[test]
    fn patcher() {
        let patch_file = "/home/jonas/Downloads/00083to00084.patch";
        let mut patch = WzPatch::open(patch_file).unwrap();
        let mut patcher = WzPatcher::new("/home/jonas/Games/gms83_1/");

        patch.process(&mut patcher).unwrap();

    }

    #[test]
    fn patcher_info() {
        let patch_file = "/home/jonas/Downloads/00072to00073.patch";
        let mut patch = WzPatch::open(patch_file).unwrap();
        let mut info = WzPatcherInfo::default();

        patch.process(&mut info).unwrap();
        dbg!(&info);

    }
}
