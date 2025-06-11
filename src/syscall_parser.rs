use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::SyscallParserFn;
use crate::syscall_event::SyscallEvent;
use crate::syscall_parsers_file::delete::parse_unlinkat;
use crate::syscall_parsers_file::open_close::{parse_close, parse_openat, parse_openat2};
use crate::syscall_parsers_file::rw::parse_fchmodat;
use crate::syscall_parsers_file::rw::{
    parse_chdir, parse_fchdir, parse_fchmod, parse_read, parse_write,
};
use crate::syscall_parsers_process::{parse_clone, parse_clone3, parse_execve, parse_execveat};
use crate::syscall_parsers_socket::{
    parse_bind, parse_connect, parse_listen, parse_recvfrom, parse_recvmsg,
};

use crate::trace_process::TraceProcess;

#[cfg(target_arch = "x86_64")]
use crate::syscall_parsers_file::delete::parse_unlink_rmdir;
#[cfg(target_arch = "x86_64")]
use crate::syscall_parsers_file::open_close::{parse_creat, parse_open};
// #[cfg(target_arch = "x86_64")]
// use crate::syscall_parsers_socket::parse_recv;

use std::ffi::c_long;
use syscall_numbers::*;

// const E_NO_SYS: u64 = (-(38i64)) as u64;
#[cfg(target_arch = "aarch64")]
pub(crate) fn syscall_parser(id: u64) -> SyscallParserFn {
    let cid: c_long = id as i64;
    if cid < 0 {
        return parse_default;
    }
    match cid {
        aarch64::SYS_openat => parse_openat,
        aarch64::SYS_openat2 => parse_openat2,
        aarch64::SYS_close => parse_close,
        aarch64::SYS_write => parse_write,
        aarch64::SYS_read => parse_read,
        aarch64::SYS_fchmod => parse_fchmod,
        aarch64::SYS_fchmodat => parse_fchmodat,
        aarch64::SYS_chdir => parse_chdir,
        aarch64::SYS_fchdir => parse_fchdir,
        aarch64::SYS_unlinkat => parse_unlinkat,
        aarch64::SYS_clone => parse_clone,
        aarch64::SYS_clone3 => parse_clone3,
        aarch64::SYS_execve => parse_execve,
        aarch64::SYS_execveat => parse_execveat,
        aarch64::SYS_connect => parse_connect,
        aarch64::SYS_bind => parse_bind,
        aarch64::SYS_listen => parse_listen,
        aarch64::SYS_recvfrom => parse_recvfrom,
        aarch64::SYS_recvmsg => parse_recvmsg,
        _ => parse_default,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn syscall_parser(id: u64) -> SyscallParserFn {
    let cid: c_long = id as i64;
    if cid < 0 {
        return parse_default;
    }
    match cid {
        x86_64::SYS_creat => parse_creat,
        x86_64::SYS_open => parse_open,
        x86_64::SYS_openat => parse_openat,
        x86_64::SYS_openat2 => parse_openat2,
        x86_64::SYS_close => parse_close,
        x86_64::SYS_write => parse_write,
        x86_64::SYS_read => parse_read,
        x86_64::SYS_chmod => parse_fchmod,
        x86_64::SYS_fchmod => parse_fchmod,
        x86_64::SYS_fchmodat => parse_fchmodat,
        x86_64::SYS_chdir => parse_chdir,
        x86_64::SYS_fchdir => parse_fchdir,
        x86_64::SYS_unlink | x86_64::SYS_rmdir => parse_unlink_rmdir,
        x86_64::SYS_unlinkat => parse_unlinkat,
        x86_64::SYS_clone => parse_clone,
        x86_64::SYS_clone3 => parse_clone3,
        x86_64::SYS_execve => parse_execve,
        x86_64::SYS_execveat => parse_execveat,
        x86_64::SYS_connect => parse_connect,
        x86_64::SYS_bind => parse_bind,
        x86_64::SYS_listen => parse_listen,
        x86_64::SYS_recvfrom => parse_recvfrom,
        x86_64::SYS_recvmsg => parse_recvmsg,
        _ => parse_default,
    }
}

fn parse_default(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    SyscallEvent::new(
        proc,
        Vec::from([
            SyscallArgument::Raw(regs.regs[0]),
            SyscallArgument::Raw(regs.regs[1]),
            SyscallArgument::Raw(regs.regs[2]),
            SyscallArgument::Raw(regs.regs[3]),
            SyscallArgument::Raw(regs.regs[4]),
            SyscallArgument::Raw(regs.regs[5]),
        ]),
        &regs,
    )
}
