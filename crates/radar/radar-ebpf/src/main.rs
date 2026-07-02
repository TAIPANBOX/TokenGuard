#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, gen::bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use core::mem;

#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub dport: u16,
    pub _pad: u16,
    pub daddr: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

const AF_INET: u16 = 2;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn radar(ctx: TracePointContext) -> u32 {
    let _ = try_radar(&ctx);
    0
}

fn try_radar(ctx: &TracePointContext) -> Result<(), i64> {
    // sys_enter_connect: uservaddr pointer at offset 24 on x86_64.
    let addr_ptr: u64 = unsafe { ctx.read_at::<u64>(24)? };
    if addr_ptr == 0 {
        return Ok(());
    }
    let mut sa: SockAddrIn = unsafe { mem::zeroed() };
    let ret = unsafe {
        bpf_probe_read_user(
            &mut sa as *mut _ as *mut core::ffi::c_void,
            mem::size_of::<SockAddrIn>() as u32,
            addr_ptr as *const core::ffi::c_void,
        )
    };
    if ret != 0 || sa.sin_family != AF_INET {
        return Ok(());
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ConnEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            (*p).pid = pid;
            (*p).dport = u16::from_be(sa.sin_port);
            (*p)._pad = 0;
            (*p).daddr = u32::from_be(sa.sin_addr);
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
