use std::collections::HashMap;

use crate::{
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_common::{EXTRA_FLAGS, read_buffer, read_cstring},
    syscall_event::{ExtraData, SyscallEvent},
    trace_process::TraceProcess,
};
use nix::libc::clone_args;

pub fn parse_clone(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    SyscallEvent::new(
        proc,
        Vec::from([
            SyscallArgument::Ptr(regs.regs[0]),
            SyscallArgument::Ptr(regs.regs[1]),
            SyscallArgument::CloneFlags(regs.regs[2] & 0xFFFFFFFF),
            SyscallArgument::Ptr(regs.regs[3]),
        ]),
        &regs,
    )
}

pub fn parse_clone3(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let extras = match read_buffer(
        proc.get_pid(),
        regs.regs[0] as usize,
        size_of::<clone_args>(),
    ) {
        Ok(args) => {
            let args: clone_args = unsafe { std::ptr::read(args.as_ptr() as *const _) };
            let flags = args.flags;
            let mut extra: ExtraData = HashMap::new();
            extra.insert(EXTRA_FLAGS, SyscallArgument::CloneFlags(flags).to_string());
            extra
        }
        Err(_) => Default::default(),
    };

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([SyscallArgument::Ptr(regs.regs[0])]),
        &regs,
        extras,
    )
}

pub fn parse_execve(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let pathname_arg = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => SyscallArgument::String(pathname),
        Err(_) => SyscallArgument::Ptr(regs.regs[0]),
    };

    SyscallEvent::new(
        proc,
        Vec::from([
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[1]),
            SyscallArgument::Ptr(regs.regs[2]),
        ]),
        &regs,
    )
}

pub fn parse_execveat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let pathname_arg = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => SyscallArgument::String(pathname),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };

    SyscallEvent::new(
        proc,
        Vec::from([
            SyscallArgument::Int(regs.regs[0]),
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
    )
}
