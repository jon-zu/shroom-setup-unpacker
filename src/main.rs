pub mod extract;
pub mod setup;
pub mod util;
pub mod patch;
pub mod patcher;

use std::{
    collections::HashSet,
    fs::File,
    io::{BufReader, BufWriter, Read},
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::Parser;
use extract::{extract_cab_split, extract_zip_split};
use humansize::{SizeFormatter, DECIMAL};
use patch::WzPatch;
use patcher::WzPatcherInfo;
use rayon::iter::{ParallelBridge, ParallelIterator};
use setup::{is, nfo300, Entry, Setup};
use util::{get_all_nested_files, SetupFormat};

fn systemtime_strftime<T>(dt: T) -> String
where
    T: Into<DateTime<Utc>>,
{
    let datetime: DateTime<Utc> = dt.into();
    datetime.format("%d/%m/%Y %T").to_string()
}

pub enum SetupOpt {
    Nfo300(nfo300::Nfo300Setup<BufReader<File>>, PathBuf),
    Is(is::IsSetup<BufReader<File>>, PathBuf),
}

impl SetupOpt {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut rdr = BufReader::new(File::open(path.as_ref())?);
        match SetupFormat::from_reader(rdr.by_ref())? {
            SetupFormat::NFO300(offset) => {
                let setup = nfo300::Nfo300Setup::new(rdr, offset)?;
                Ok(Self::Nfo300(setup, path.as_ref().to_path_buf()))
            }
            SetupFormat::InstallShield(offset) => {
                let setup = is::IsSetup::new(rdr, offset)?;
                Ok(Self::Is(setup, path.as_ref().to_path_buf()))
            }
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Nfo300(_, path) => path,
            Self::Is(_, path) => path,
        }
    }

    fn extract_setup(&mut self, tmp_dir: &Path, out_dir: &Path) -> anyhow::Result<()> {
        // Extract all entries to a temporary directory
        let out = match self {
            Self::Nfo300(setup, _) => setup.extract_to(tmp_dir),
            Self::Is(setup, _) => setup.extract_to(tmp_dir),
        }
        .context("Extracing entries")?;

        let exts = out
            .iter()
            .filter_map(|p| p.extension())
            .filter_map(|s| s.to_str())
            .collect::<HashSet<_>>();
        if exts.contains(&"cab") {
            extract_cab_split(out, out_dir)?;
        } else if exts.contains(&"zip") || exts.contains(&"z0") {
            extract_zip_split(out, out_dir)?;
        } else if exts.contains(&"msi") {
            let msi = out
                .iter()
                .find(|p| p.extension().and_then(|s| s.to_str()) == Some("msi"))
                .unwrap();
            let tmp_msi = tmp_dir.join("msi");
            std::fs::create_dir(&tmp_msi)?;
            extract::extract_msi(msi, &tmp_msi)?;

            let data_cab = tmp_msi.join("Data1.cab");
            extract_cab_split(vec![data_cab], out_dir)?;
        } else {
            anyhow::bail!("Unknown archive format: {:?}", exts);
        }

        Ok(())
    }

    fn list_archives(&mut self) -> anyhow::Result<()> {
        log::info!("Listing archives for: {}", self.path().display());
        match self {
            Self::Nfo300(setup, _) => Self::list_archives_inner(setup),
            Self::Is(setup, _) => Self::list_archives_inner(setup),
        }
    }

    fn list_archives_inner(mut setup: impl Setup) -> anyhow::Result<()> {
        match setup.entries() {
            Ok(entries) => {
                for entry in entries.iter() {
                    log::info!(
                        "{} - {}",
                        entry.name(),
                        SizeFormatter::new(entry.size(), DECIMAL)
                    );
                }

                let total: u64 = entries.iter().map(|e| e.size()).sum();
                let sz = setup.size();
                let perc = (total as f64 / sz as f64) * 100.0;
                log::info!(
                    "Total: {}/{} ({perc:.2}%)",
                    SizeFormatter::new(total, DECIMAL),
                    SizeFormatter::new(sz, DECIMAL)
                );
            }
            Err(e) => log::error!("Error: {}", e),
        }

        Ok(())
    }

    fn extract_and_report(
        &mut self,
        id: usize,
        remove_prefix: &[String],
        remove_exts: &[String],
        out_dir: &Path,
        keep_tmp: bool,
    ) -> anyhow::Result<()> {
        let name = self.path().file_stem().context("Invalid setup path")?;
        let out_dir = out_dir.join(name);

        let tmp_dir = std::env::temp_dir().join(format!("mssetupx{id}"));
        // Ensure it's clean
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir)?;
        std::fs::create_dir_all(&out_dir).context("Create out dir")?;
        self.extract_setup(&tmp_dir, &out_dir)?;
        Self::create_report_and_clean_up(&out_dir, remove_prefix, remove_exts)?;
        if !keep_tmp {
            std::fs::remove_dir_all(tmp_dir)?;
        }

        Ok(())
    }

    fn create_report_and_clean_up(
        dir: &Path,
        remove_prefix: &[String],
        remove_exts: &[String],
    ) -> anyhow::Result<()> {
        use std::io::Write;
        let entries = get_all_nested_files(dir)?;

        // Create report
        let report = dir.join("report.txt");
        let mut report = BufWriter::new(File::create(&report)?);
        for entry in entries.iter() {
            let meta = entry.metadata()?;
            let name = entry.file_name().unwrap().to_string_lossy();
            let acc = systemtime_strftime(meta.accessed().unwrap());
            let cre = systemtime_strftime(meta.created().unwrap());

            writeln!(
                report,
                "{} - {} - {cre} - {acc}",
                name,
                SizeFormatter::new(meta.len(), DECIMAL)
            )?;
        }

        for entry in entries.iter() {
            let name = entry.file_name().unwrap().to_string_lossy();
            let name = name.to_string();

            #[allow(clippy::search_is_some)]
            let has_prefix = remove_prefix
                .iter()
                .find(|p| name.starts_with(p.as_str()))
                .is_some();

            #[allow(clippy::search_is_some)]
            let has_ext = remove_exts
                .iter()
                .find(|e| entry.extension().and_then(|s| s.to_str()) == Some(e))
                .is_some();

            if has_prefix || has_ext {
                if let Err(err) = std::fs::remove_file(entry) {
                    log::error!("Error Deleting File({}): {err}", entry.display());
                }
            }
        }

        Ok(())
    }
}

fn list_patcher(p: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut patcher = WzPatch::open(&p)?;
    let mut info = WzPatcherInfo::default();
    patcher.process(&mut info)?;

    log::info!("Patcher: {}", p.as_ref().display());
    log::info!("Version: {}", patcher.version());
    log::info!("Added");
    for entry in info.added_files.iter() {
        log::info!("\t{} - {}", entry.0, SizeFormatter::new(entry.1, DECIMAL));
    }

    log::info!("Modified");
    for entry in info.modified_files.iter() {
        log::info!("\t{} - {}", entry.0, SizeFormatter::new(entry.1, DECIMAL));
    }

    log::info!("Deleted");
    for entry in info.removed_files.iter() {
        log::info!("\t{}", entry);
    }


    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum Args {
    Extract {
        /// The setup file to extract
        #[arg(short, long)]
        setup: String,

        /// The setup directory
        #[arg(short, long, default_value = "setup")]
        dir: String,

        /// Keep the tmp dir
        #[arg(short, long, default_value = "false")]
        keep_tmp: bool,
    },
    ExtractAll {
        #[arg(short, long)]
        setup_glob: String,
        #[arg(
            long,
            default_value = "",
            use_value_delimiter = true,
            value_delimiter = ','
        )]
        remove_prefix: Vec<String>,
        #[arg(
            long,
            default_value = "",
            use_value_delimiter = true,
            value_delimiter = ','
        )]
        remove_exts: Vec<String>,
        #[arg(short, long)]
        out_dir: String,
        #[arg(short, long, default_value = "4")]
        threads: usize,
        /// Keep the tmp dir
        #[arg(short, long, default_value = "false")]
        keep_tmp: bool,
    },
    ListArchives {
        /// The setup file to list
        #[arg(short, long)]
        setup: String,
    },
    ListAllArchives {
        /// The setup file to list
        #[arg(short, long)]
        setup_glob: String,
    },
    ListPatcher {
        /// The patcher file to list
        #[arg(short, long)]
        patcher: String,
    },
    ListAllPatchers {
        /// The patcher file to list
        #[arg(short, long)]
        patcher_glob: String,
    },
}

fn main() -> anyhow::Result<()> {
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        simplelog::Config::default(),
        simplelog::TerminalMode::Mixed,
        simplelog::ColorChoice::Auto,
    )?;

    let args = Args::parse();

    match args {
        Args::Extract {
            setup,
            dir,
            keep_tmp,
        } => {
            let mut setup = SetupOpt::open(&setup)?;
            if let Err(err) = setup.extract_and_report(0, &[], &[], Path::new(&dir), keep_tmp) {
                log::error!("Error: {err} for: {}", setup.path().display());
            }
        }
        Args::ListArchives { setup } => {
            let mut setup = SetupOpt::open(&setup)?;
            setup.list_archives()?;
        }
        Args::ListAllArchives { setup_glob } => {
            let paths = glob::glob(&setup_glob)?.collect::<Result<Vec<_>, _>>()?;
            for path in paths {
                let mut setup = SetupOpt::open(&path)?;
                setup.list_archives()?;
            }
        }
        Args::ExtractAll {
            setup_glob,
            remove_prefix,
            remove_exts,
            out_dir,
            threads,
            keep_tmp
        } => {
            let _ = std::fs::create_dir_all(&out_dir);
            let paths = glob::glob(&setup_glob)?.collect::<Result<Vec<_>, _>>()?;
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .unwrap();
            paths
                .iter()
                .enumerate()
                .par_bridge()
                .for_each(|(id, path)| {
                    if let Err(err) = SetupOpt::open(path).and_then(|mut setup| {
                        setup.extract_and_report(
                            id,
                            &remove_prefix,
                            &remove_exts,
                            Path::new(&out_dir),
                            keep_tmp
                        )
                    }) {
                        log::error!("Error: {} for: {}", err, path.display());
                    }
                });
        },
        Args::ListPatcher { patcher } => {
            if let Err(err) = list_patcher(&patcher) {
                log::error!("Error: {err} for: {}", patcher);
            }
        },
        Args::ListAllPatchers { patcher_glob } => {
            let paths = glob::glob(&patcher_glob)?.collect::<Result<Vec<_>, _>>()?;
            for path in paths {
                if let Err(err) = list_patcher(&path) {
                    log::error!("Error: {err} for: {}", path.display());
                }
            }
        }
    }

    Ok(())
}