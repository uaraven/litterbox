use std::cmp::min;
use std::collections::HashMap;

use crate::strace::TraceProcess;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{read_buffer, read_cstring, EXTRA_PATHNAME, MAX_BUFFER_SIZE};
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

pub fn parse_open(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);

    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
    };

    let flags = regs.regs[1];
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        if !is_entry {
            proc.add_fd(regs.return_value as i64, EXTRA_PATHNAME, pathname.clone());
        }
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::OpenFlags(flags)]),
        &regs,
        extra,
    )
}

pub fn parse_openat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };

    let flags = regs.regs[2];
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        if !is_entry {
            proc.add_fd(regs.return_value as i64, EXTRA_PATHNAME, pathname.clone());
        }
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(regs.regs[0]),
            pathname_arg,
            SyscallArgument::OpenFlags(flags),
        ]),
        &regs,
        extra,
    )
}

pub fn parse_openat2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        if !is_entry {
            proc.add_fd(regs.return_value as i64, EXTRA_PATHNAME, pathname.clone());
        }
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(regs.regs[0]),
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
        extra,
    )
}

pub fn parse_close(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    if is_entry {
        proc.remove_fd(regs.regs[0] as i64);
    }
    SyscallEvent::new(proc, Vec::from([SyscallArgument::Fd(regs.regs[0])]), &regs)
}

pub fn parse_write(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();

    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = match is_entry {
        true => regs.regs[0],
        false => proc
            .get_last_syscall(regs.syscall_id)
            .map(|event| event.regs.regs[0])
            .unwrap_or(regs.regs[0]),
    };
    if let Some(fd_data) = proc.get_fd(fd as i64) {
        extras.insert(fd_data.name, fd_data.value.clone());
    };
    let read_size = min(MAX_BUFFER_SIZE, regs.regs[2] as usize);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, read_size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

pub fn parse_read(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = match is_entry {
        true => regs.regs[0],
        false => proc
            .get_last_syscall(regs.syscall_id)
            .map(|event| event.regs.regs[0])
            .unwrap_or(regs.regs[0]),
    };
    if let Some(fd_data) = proc.get_fd(fd as i64) {
        extras.insert(fd_data.name, fd_data.value.clone());
    };
    let read_size = min(MAX_BUFFER_SIZE, regs.regs[2] as usize);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, read_size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}
