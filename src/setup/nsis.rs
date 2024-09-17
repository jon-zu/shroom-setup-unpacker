use std::io::{BufRead, Cursor, Read, Seek};

use bytemuck::{Pod, Zeroable};

const SIG_LEN: usize = 16;

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct NsisFlags: u32 {
        const UINSTALL = 1;
        const SILENT = 2;
        const NO_CRC = 4;
        const FORCE_CRC = 8;
        const BI_LONG_OFFSET = 16;
        const BI_EXTERNAL_FILE_SUPPORT = 32;
        const BI_EXTERNAL_FILE = 64;
        const BI_IS_STUB_INSTALLER = 128;
    }
}

#[derive(Debug, Default, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct NsisHeader {
    pub flags: u32,
    pub sig_info: u32,
    pub magic: [u8; 12],
    pub header_len: u32,
    pub data_len: u32,
}

#[derive(Debug, Default, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct BlockHeader {
    pub offset: u32,
    pub num: u32,
}

#[derive(Debug, Default, Copy, Clone, Pod, Zeroable)]
#[repr(C, packed)]
pub struct Hdr {
    pub flags: u32,
    pub block_sections: BlockHeader,
    pub block_entries: BlockHeader,
    pub block_strings: BlockHeader,
    pub block_lang: BlockHeader,
    pub block_ctl_colors: BlockHeader,
    pub block_data: BlockHeader,

    pub install_reg_root: u32,
    pub install_reg_key: u32,
    pub install_reg_value: u32,
}

impl NsisHeader {
    pub fn flags(&self) -> NsisFlags {
        NsisFlags::from_bits_truncate(self.flags)
    }
}

#[derive(Debug)]
pub struct Nsis<R> {
    rdr: R,
    hdr: NsisHeader,
    offset: u64,
}
impl<R: BufRead + Read + Seek> Nsis<R> {
    pub fn new(mut rdr: R, offset: u64) -> anyhow::Result<Self> {
        rdr.seek(std::io::SeekFrom::Start(offset))?;
        let mut hdr = NsisHeader::zeroed();
        rdr.read_exact(bytemuck::bytes_of_mut(&mut hdr))?;
        Ok(Self { rdr, hdr, offset })
    }

    pub fn decode_bzip(&mut self) -> anyhow::Result<()> {
        self.rdr.seek(std::io::SeekFrom::Start(0x0F264FBC))?;



        let mut dec = bzip2::bufread::BzDecoder::new(&mut self.rdr);
        let mut out = std::fs::File::create("out.bin")?;
        std::io::copy(&mut dec, &mut out)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::*;

    #[test]
    fn nsis() {
        let nsis_file = "/home/jonas/Downloads/CMS_v64_broken/Maplestory064.exe";
        let file = BufReader::new(std::fs::File::open(nsis_file).unwrap());
        let offset = 0x0000DBFC;
        let mut nsis = Nsis::new(file, offset).unwrap();
        dbg!(&nsis);
        dbg!(nsis.hdr.flags());

        nsis.decode_bzip().unwrap();
    }
}
