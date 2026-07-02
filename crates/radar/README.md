# TokenFuse Radar (eBPF) — W1

Linux-only. Discovers **LLM traffic and shadow agents** on a host with **zero
config in the apps**: an eBPF program on the `sys_enter_connect` tracepoint
reports every outbound TCP connection (pid, comm, dest ip:port) and flags those
going to known LLM providers or local model servers (Ollama/vLLM).

This crate is its own nested workspace and is **excluded from the default
workspace** (it needs a Linux kernel, nightly Rust, and `bpf-linker`), so the
main `cargo build` / CI stay light.

## Build & run (Linux, as root)

```bash
# prerequisites
sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

cd crates/radar
cargo build
sudo ./target/debug/tokenfuse-radar
```

Then make an LLM call from anywhere on the box and watch it appear, e.g.:

```
PID      COMM             DEST                  FLAG
14113    curl             162.159.140.245:443     <== LLM provider
14117    curl             127.0.0.1:11434         <== local Ollama
```

Requires a kernel with BTF (`/sys/kernel/btf/vmlinux`) — standard on modern
Ubuntu. Verified on Ubuntu 24.04, kernel 7.0.
