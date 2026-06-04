mod ntfs;

use std::path::PathBuf;

use anyhow::Context;
use base64::Engine;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ntfsdump",
    version,
    about = "Windows protected-file acquisition over raw NTFS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire SAM and SYSTEM hives into an output directory.
    Dump {
        /// Directory where acquired hives will be written.
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Include the SECURITY hive as well.
        #[arg(long)]
        security: bool,
    },

    /// Copy one or more protected files through raw NTFS reads.
    Copy {
        /// Directory where copied files will be written.
        #[arg(short, long)]
        out: PathBuf,

        /// Absolute Windows paths, for example C:\Windows\System32\config\SAM.
        #[arg(required = true)]
        paths: Vec<String>,
    },

    /// Read one protected file and return base64 or write raw bytes to a file.
    Read {
        /// Absolute Windows path to read.
        path: String,

        /// Write raw bytes to this file instead of printing base64.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Dump { out, security } => {
            std::fs::create_dir_all(&out)
                .with_context(|| format!("creating output directory {}", out.display()))?;
            let out = output_dir_to_windows_string(&out);
            let report = ntfs::dump_hives(&out, security)?;
            println!("{report}");
        }
        Command::Copy { out, paths } => {
            std::fs::create_dir_all(&out)
                .with_context(|| format!("creating output directory {}", out.display()))?;
            let out = output_dir_to_windows_string(&out);
            let report = ntfs::copy_paths(&paths, &out)?;
            println!("{report}");
        }
        Command::Read { path, out } => {
            let data = ntfs::read_path(&path)?;
            if let Some(out) = out {
                if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("creating output directory {}", parent.display())
                    })?;
                }
                std::fs::write(&out, &data)
                    .with_context(|| format!("writing {}", out.display()))?;
                println!("[+] {} -> {} ({} bytes)", path, out.display(), data.len());
            } else {
                println!(
                    "[+] Read {} bytes from {}\n[base64]\n{}",
                    data.len(),
                    path,
                    base64::engine::general_purpose::STANDARD.encode(data)
                );
            }
        }
    }

    Ok(())
}

fn output_dir_to_windows_string(path: &PathBuf) -> String {
    path.to_string_lossy().replace('/', "\\")
}
