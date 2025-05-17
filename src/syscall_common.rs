use nix::sys::ptrace;
use nix::unistd::Pid;
use syscall_numbers::native;

use std::os::raw::c_long;

use crate::regs::Regs;
use crate::syscall_event::SyscallEvent;
use crate::trace_process::TraceProcess;

pub const EXTRA_PATHNAME: &str = "pathname";
pub const EXTRA_ADDR: &str = "addr";
pub const EXTRA_FLAGS: &str = "flags";
pub const EXTRA_DIRFD: &str = "dirfd";

pub const MAX_BUFFER_SIZE: usize = 32;

pub type SyscallParserFn = fn(tracer: &mut TraceProcess, regs: Regs) -> SyscallEvent;

pub fn get_syscall_name(id: u64) -> String {
    let default_name = format!("syscall_{}", id);
    native::sys_call_name(id as i64)
        .map(|a| a.to_string())
        .unwrap_or(default_name)
}

pub fn read_cstring(pid: Pid, mut addr: usize) -> Result<String, nix::Error> {
    let mut bytes = Vec::new();

    loop {
        let word = ptrace::read(pid, addr as ptrace::AddressType)? as c_long;
        let word_bytes = word.to_ne_bytes();

        for &b in &word_bytes {
            if b == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(b);
        }

        addr += size_of::<c_long>();
    }
}

pub fn read_buffer(pid: Pid, mut addr: usize, size: usize) -> Result<Vec<u8>, nix::Error> {
    let mut bytes = Vec::new();
    let mut count = 0;
    loop {
        let word = ptrace::read(pid, addr as ptrace::AddressType)? as c_long;
        let word_bytes = word.to_ne_bytes();

        for &b in &word_bytes {
            if count >= size {
                return Ok(bytes);
            }
            bytes.push(b);
            count += 1;
        }

        addr += size_of::<c_long>();
    }
}

pub fn read_buffer_as_type<T>(pid: Pid, mut addr: usize) -> Result<T, nix::Error> {
    let size = std::mem::size_of::<T>();
    let mem = match read_buffer(pid, addr, size) {
        Ok(mem) => mem,
        Err(e) => {
            return Err(e);
        }
    };
    let buf: T = unsafe { std::ptr::read(mem.as_ptr() as *const _) };
    Ok(buf)
}
