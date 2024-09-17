use std::{
    fs::File,
    io::{self, Seek},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context;
use zipunsplitlib::file::{JoinedFile, MemoryCowFile, Opener};

pub struct JoinedOpener(pub Vec<PathBuf>);

impl Opener for JoinedOpener {
    fn open_split(&mut self, index: usize) -> io::Result<File> {
        File::open(&self.0[index])
    }

    fn num_splits(&self) -> usize {
        self.0.len()
    }
}

pub fn extract_zip_split(paths: Vec<PathBuf>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
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

/*#[cfg(not(target_os = "windows"))]
fn extract_cab_split(paths: Vec<PathBuf>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    use std::process::Command;

    Command::new("cabextract")
        .args(["-d", setup_dir.as_ref().to_str().unwrap()])
        .args(paths.iter().map(|p| p.to_str().unwrap()))
        .output()?;

    Ok(())
}*/

fn z7() -> Command {
    Command::new(if cfg!(windows) {
        "C:\\Program Files\\7-Zip\\7z.exe"
    } else {
        "7z"
    })
}

pub fn extract_cab_split(paths: Vec<PathBuf>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    z7()
        .args(["x", "-y"])
        .arg(format!("-o{}", setup_dir.as_ref().to_str().unwrap()))
        .arg(paths[0].to_str().unwrap())
        .output()?;

    Ok(())
}

pub fn extract_msi(path: impl AsRef<Path>, setup_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    z7()
        .args(["x", "-y"])
        .arg(format!("-o{}", setup_dir.as_ref().to_str().unwrap()))
        .arg(path.as_ref().to_str().unwrap())
        .output()?;

    Ok(())
}
