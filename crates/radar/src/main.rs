//! TokenFuse Radar (W1): eBPF-based discovery of LLM traffic / shadow agents.
//!
//! Attaches to the `sys_enter_connect` tracepoint and reports every outbound
//! TCP connection (pid, comm, dest ip:port), flagging those that go to known
//! LLM providers or local model servers — with zero configuration in the apps.

use std::collections::HashSet;
use std::net::{Ipv4Addr, ToSocketAddrs};

use aya::maps::RingBuf;
use aya::programs::TracePoint;

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent {
    pid: u32,
    dport: u16,
    _pad: u16,
    daddr: u32,
    comm: [u8; 16],
}

fn resolve_llm_ips() -> HashSet<Ipv4Addr> {
    let hosts = [
        "api.anthropic.com:443",
        "api.openai.com:443",
        "generativelanguage.googleapis.com:443",
    ];
    let mut set = HashSet::new();
    for h in hosts {
        if let Ok(addrs) = h.to_socket_addrs() {
            for a in addrs {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    set.insert(v4);
                }
            }
        }
    }
    set
}

fn is_llm(ip: Ipv4Addr, port: u16, llm: &HashSet<Ipv4Addr>) -> Option<&'static str> {
    if llm.contains(&ip) {
        Some("LLM provider")
    } else if port == 11434 {
        Some("local Ollama")
    } else if port == 8000 || port == 8001 {
        Some("local vLLM?")
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/radar"
    )))?;
    let program: &mut TracePoint = ebpf.program_mut("radar").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_connect")?;

    let llm = resolve_llm_ips();
    println!(
        "tokenfuse-radar: watching outbound connections (known LLM IPs: {})",
        llm.len()
    );
    println!("{:<8} {:<16} {:<21} {}", "PID", "COMM", "DEST", "FLAG");

    let mut ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    loop {
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<ConnEvent>() {
                continue;
            }
            let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnEvent) };
            let ip = Ipv4Addr::from(ev.daddr);
            if ev.dport == 0 {
                continue; // ignore name-resolution / non-TCP noise
            }
            if ip.is_loopback() && ev.dport != 11434 && ev.dport != 8000 {
                continue; // skip local chatter unless a model port
            }
            let comm = String::from_utf8_lossy(&ev.comm)
                .trim_end_matches('\0')
                .to_string();
            if comm == "tokenfuse-radar" {
                continue; // don't report our own resolver connections
            }
            let flag = is_llm(ip, ev.dport, &llm).unwrap_or("");
            let marker = if flag.is_empty() { "" } else { "  <== " };
            println!(
                "{:<8} {:<16} {:<21} {marker}{flag}",
                ev.pid,
                comm,
                format!("{ip}:{}", ev.dport)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
