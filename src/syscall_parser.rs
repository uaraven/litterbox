use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::SyscallParserFn;
use crate::syscall_event::SyscallEvent;
use crate::syscall_ids::*;
use crate::syscall_parsers_file::{
    parse_chdir, parse_close, parse_creat, parse_fchdir, parse_fchmod, parse_open, parse_openat,
    parse_openat2, parse_read, parse_write,
};
use crate::syscall_parsers_process::{parse_clone, parse_clone3, parse_execve, parse_execveat};
use crate::syscall_parsers_socket::{
    parse_bind, parse_connect, parse_listen, parse_recv, parse_recvfrom, parse_recvmsg,
};
use crate::trace_process::TraceProcess;

use std::ffi::c_long;
use syscall_numbers::*;

// const E_NO_SYS: u64 = (-(38i64)) as u64;
pub fn syscall_parser(id: u64) -> SyscallParserFn {
    let cid: c_long = id as i64;
    if cid < 0 {
        return parse_default;
    }
    // special handling for syscalls that don't exist on arm64
    if cid == SYS_CREAT {
        return parse_creat;
    }
    if cid == SYS_OPEN {
        return parse_open;
    }
    if cid == SYS_RECV {
        return parse_recv;
    }
    match cid {
        native::SYS_openat => parse_openat,
        native::SYS_openat2 => parse_openat2,
        native::SYS_close => parse_close,
        native::SYS_write => parse_write,
        native::SYS_read => parse_read,
        native::SYS_fchmod => parse_fchmod,
        native::SYS_chdir => parse_chdir,
        native::SYS_fchdir => parse_fchdir,
        native::SYS_clone => parse_clone,
        native::SYS_clone3 => parse_clone3,
        native::SYS_execve => parse_execve,
        native::SYS_execveat => parse_execveat,
        native::SYS_connect => parse_connect,
        native::SYS_bind => parse_bind,
        native::SYS_listen => parse_listen,
        native::SYS_recvfrom => parse_recvfrom,
        native::SYS_recvmsg => parse_recvmsg,
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
