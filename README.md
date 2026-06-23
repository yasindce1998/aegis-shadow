<div align="center">

<img src="assets/logo.svg" width="120" alt="Aegis-Shadow"/>

# AEGIS-SHADOW

[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)
[![Kernel](https://img.shields.io/badge/kernel-5.10+-green.svg)](https://www.kernel.org/)

</div>

---

## Overview

Aegis-Shadow is an educational research project that demonstrates both offensive and
defensive uses of Linux eBPF technology. It consists of two modules:

- **Shadow** (Offense): An eBPF-based rootkit with 47+ features spanning process hiding,
  XDP-based C2 with ChaCha20 encryption and HMAC authentication, file obfuscation,
  credential harvesting, DNS exfiltration, ICMP covert channels, network namespace hiding,
  eBPF program cloaking, container escape probes, anti-forensics bytecode wiping, plus
  9 advanced modules: hypervisor evasion, polymorphic engine, phantom network stack,
  cross-container lateral movement, DMA covert channels, behavioral AI camouflage,
  supply chain persistence, dead man's switch, and BPF parasitism.
- **Aegis** (Defense): A runtime detection engine with 14 eBPF-based detection modules
  plus intelligent user-space analysis including anomaly scoring, attack chain
  correlation, calibration-based baselines, auto-detach of malicious programs,
  process containment, honeypot maps, and hot-reloadable configuration.

## Warning

**This project is for educational and research purposes only.**

- ALL development and testing MUST occur within isolated virtual machines.
- NEVER run the offensive module on production systems, shared networks, or systems you do not own.
- The VM MUST use a host-only network adapter during testing.
- Do NOT distribute compiled rootkit binaries.

## Requirements

- **Host**: macOS/Linux with UTM, QEMU, or VirtualBox
- **Guest VM**: Ubuntu 24.04 LTS, Linux Kernel 6.8+
- **Rust**: Nightly toolchain
- **Tools**: bpf-linker, bpftool, clang, llvm, libelf-dev

## Quick Start

```bash
# 1. Set up VM and verify environment
bash verify-env.sh

# 2. Build everything
make build

# 3. Start offensive rootkit (loads core features)
sudo ./target/release/offense --iface eth0 --hide-pid 1234

# 4. Run defense detection (in another terminal)
sudo ./target/release/defense --all-modules --verbose

# 5. Stop programs
# Press Ctrl+C in each terminal, or:
sudo pkill offense
sudo pkill defense
```

## Project Structure

| Directory | Purpose |
|---|---|
| `common/` | Shared data structures and constants (`#![no_std]`) |
| `offense-ebpf/` | Kernel-space rootkit eBPF programs (47+ features) |
| `offense/` | User-space rootkit loader and CLI |
| `defense-ebpf/` | Kernel-space defensive eBPF probes (11 detectors) |
| `defense/` | User-space detection engine and CLI |
| `xtask/` | Build automation |
| `integration-tests/` | Adversarial offense-vs-defense test suite |

## Usage

### Offense (Rootkit)

The offense module loads the core 13 rootkit features automatically on startup. Additional features are enabled via flags:

```bash
# Basic usage - loads core features
sudo ./target/release/offense --iface eth0

# With extended features enabled
sudo ./target/release/offense \
    --iface eth0 \
    --hide-pid 1234 \
    --obfuscate-inode 98765 \
    --monitor-tty 136:0 \
    --pin-maps \
    --enable-icmp-exfil \
    --enable-container-probe
```

**Available flags:**

| Flag | Description |
|---|---|
| `--iface <name>` | Network interface for XDP/TC attachment |
| `--verbose` | Enable debug-level logging |
| `--hide-pid <pid>` | Add a PID to the hidden process list on startup |
| `--obfuscate-inode <inode>` | Add an inode to the file obfuscation list |
| `--monitor-tty <major:minor>` | Monitor a TTY device for credential harvesting |
| `--spoof-ppid <pid:fake_ppid>` | Spoof a process's parent PID |
| `--timestomp <inode:atime:mtime:ctime>` | Set fake timestamps (epoch seconds) |
| `--pin-maps` | Pin BPF maps to `/sys/fs/bpf/shadow` for persistence |
| `--enable-netns-hide` | Enable network namespace hiding |
| `--enable-bpf-cloak` | Enable eBPF program cloaking (hides own prog IDs) |
| `--enable-module-mask` | Enable kernel module masquerading in /proc/modules |
| `--enable-memfd` | Enable memory-only payload staging (memfd + execveat) |
| `--enable-syslog-strip` | Enable syslog write stripping |
| `--wipe-bytecode` | Activate anti-forensics bytecode wipe (programs become no-ops) |
| `--enable-icmp-exfil` | Enable ICMP covert channel exfiltration |
| `--enable-socket-clone` | Enable socket cloning / connection shadowing |
| `--enable-cred-relay` | Enable credential relay over C2 |
| `--enable-container-probe` | Enable container escape probes |
| `--enable-hypervisor-evasion` | Enable hypervisor detection and evasion (CPUID, hypercall, TSC) |
| `--enable-polymorphic` | Enable polymorphic engine (bytecode morphing, pattern rotation) |
| `--enable-phantom-stack` | Enable phantom network stack (invisible TCP connections) |
| `--enable-container-lateral` | Enable cross-container lateral movement via cgroup/namespace abuse |
| `--enable-dma-covert` | Enable DMA covert channel (IOMMU, PCIe TLP, NIC exfil) |
| `--enable-behavioral-ai` | Enable behavioral AI camouflage (syscall profiling, activity throttling) |
| `--enable-supply-chain` | Enable supply chain persistence (package manager hooking, binary patching) |
| `--enable-deadman-switch` | Enable dead man's switch (heartbeat monitor, scorched earth wipe) |
| `--enable-bpf-parasitism` | Enable BPF parasitism (prog scanning, tail-call injection, array hijack) |

### Defense (Detection Engine)

The defense module enables detection modules via flags and provides intelligent alert analysis:

```bash
# Enable all detection modules
sudo ./target/release/defense --all-modules

# Enable specific modules with hot-reload config
sudo ./target/release/defense \
    --ghost-maps \
    --syscall-latency \
    --bytecode-check \
    --prog-inventory \
    --memfd-detect \
    --honeypots \
    --config /etc/aegis/config.json \
    --output /tmp/alerts.json

# With active response enabled
sudo ./target/release/defense --all-modules \
    --auto-detach \
    --auto-contain \
    --threshold 3
```

**Available flags:**

| Flag | Description |
|---|---|
| `--verbose` / `-v` | Enable debug-level logging |
| `--output` / `-o` | Path to write JSON alert records |
| `--threshold` / `-t` | Alert severity threshold: 1=Low, 2=Medium (default), 3=High, 4=Critical |
| `--all-modules` | Enable all detection modules |
| `--ghost-maps` | Enable ghost map detection |
| `--syscall-latency` | Enable syscall latency monitoring |
| `--bytecode-check` | Enable bytecode integrity checking |
| `--hidden-process` | Enable hidden process detection |
| `--suspicious-hooks` | Enable suspicious hook detection |
| `--prog-inventory` | Enable eBPF program inventory (ID gap detection) |
| `--syscall-anomaly` | Enable syscall argument anomaly profiling |
| `--net-baseline` | Enable network behavior baseline |
| `--memfd-detect` | Enable memory-backed execution detection |
| `--map-audit` | Enable BPF map content auditing |
| `--tracepoint-monitor` | Enable tracepoint coverage monitoring (rapid detach detection) |
| `--auto-detach` | Automatic detachment of malicious BPF programs |
| `--auto-contain` | Automatic process containment via cgroups |
| `--honeypots` | Enable honeypot BPF maps |
| `--calibration-period` | Baseline calibration duration in seconds (default: 60) |
| `--config` | Path to runtime config JSON file (hot-reloaded every 5s) |

For detailed usage examples, see [USAGE.md](USAGE.md)

## Running Tests

```bash
# Run integration tests (user-space, no root required)
cargo test -p integration-tests

# Run automated test scripts (requires root, in VM)
sudo ./tests/test_offense.sh
sudo ./tests/test_defense.sh

# Or use Makefile
make test
```

For manual testing procedures, see [USAGE.md](USAGE.md#testing)

## License

This project is provided for educational purposes only. See Section 13 of the PRD
for full safety and legal guidelines.
