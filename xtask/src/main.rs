use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Subcommand)]
enum XtaskCommand {
    /// Build the eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + user-space)
    BuildAll {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        XtaskCommand::BuildEbpf { release } => build_ebpf(release),
        XtaskCommand::BuildAll { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;

    // Build offense-ebpf
    println!("Building offense-ebpf...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=offense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build offense-ebpf")?;
    if !status.success() {
        bail!("offense-ebpf build failed");
    }

    // Build defense-ebpf
    println!("Building defense-ebpf...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=defense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build defense-ebpf")?;
    if !status.success() {
        bail!("defense-ebpf build failed");
    }

    println!("eBPF build complete.");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;

    println!("Building user-space binaries...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("build")
        .arg("--package=offense")
        .arg("--package=defense");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build user-space")?;
    if !status.success() {
        bail!("user-space build failed");
    }

    println!("User-space build complete.");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .context("Failed to locate workspace root")?;
    let path = String::from_utf8(output.stdout)?;
    Ok(PathBuf::from(path.trim()).parent().unwrap().to_path_buf())
}

// Made with Bob
