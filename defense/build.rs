use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ebpf_dir = PathBuf::from("../target/bpfel-unknown-none/release");

    println!("cargo:rerun-if-changed=../defense-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed={}", ebpf_dir.display());
}

// Made with Bob
