use std::{
    cmp::min,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use nix::{
    libc::{self, sockaddr},
    unistd::Pid,
};

use crate::{
    regs::Regs,
    strace::TraceProcess,
    syscall_args::SyscallArgument,
    syscall_common::{read_buffer, read_cstring, EXTRA_ADDR, MAX_BUFFER_SIZE},
    syscall_event::{ExtraData, SyscallEvent},
};

fn get_sockaddr_as_arg(pid: Pid, regs: &Regs, reg_ptr: usize, reg_size: usize) -> SyscallArgument {
    let size = min(regs.regs[reg_size] as usize, MAX_BUFFER_SIZE);
    if let Ok(addr) = read_buffer(pid, regs.regs[reg_ptr] as usize, size) {
        let sockaddr: sockaddr = unsafe { std::ptr::read(addr.as_ptr() as *const _) };
        let arg = match sockaddr.sa_family as i32 {
            libc::AF_INET => {
                let addr = unsafe { std::ptr::read(addr.as_ptr() as *const libc::sockaddr_in) };
                let port = u16::from_be(addr.sin_port);
                SyscallArgument::IpV4Address {
                    addr: Ipv4Addr::from_bits(addr.sin_addr.s_addr),
                    port: port,
                }
            }
            libc::AF_INET6 => {
                let saddr = unsafe { std::ptr::read(addr.as_ptr() as *const libc::sockaddr_in6) };
                let addr = u128::from_be_bytes(saddr.sin6_addr.s6_addr);
                let port = u16::from_be(saddr.sin6_port);
                SyscallArgument::IpV6Address {
                    addr: Ipv6Addr::from_bits(addr),
                    port: port,
                }
            }
            libc::AF_UNIX => {
                let addr = unsafe { std::ptr::read(addr.as_ptr() as *const libc::sockaddr_un) };
                let path = read_cstring(pid, addr.sun_path.as_ptr() as usize);
                SyscallArgument::UnixAddress {
                    addr: path.unwrap_or(String::new()),
                }
            }
            _ => SyscallArgument::Ptr(regs.regs[1]),
        };
        arg
    } else {
        SyscallArgument::Ptr(regs.regs[1])
    }
}

pub fn parse_connect(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let arguments = Vec::from([
        SyscallArgument::Int(regs.regs[0]),
        get_sockaddr_as_arg(proc.get_pid(), &regs, 1, 2),
        SyscallArgument::Int(regs.regs[2]),
    ]);

    let address = arguments.get(1).unwrap().to_string();
    if is_entry {
        proc.add_fd(regs.regs[0] as i64, EXTRA_ADDR, address);
    }
    SyscallEvent::new(proc, arguments, &regs)
}

pub fn parse_bind(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let arguments = Vec::from([
        SyscallArgument::Fd(regs.regs[0]),
        get_sockaddr_as_arg(proc.get_pid(), &regs, 1, 2),
        SyscallArgument::Int(regs.regs[2]),
    ]);

    let address = arguments.get(1).unwrap().to_string();
    if is_entry {
        proc.add_fd(regs.regs[0] as i64, EXTRA_ADDR, address);
    }
    SyscallEvent::new(&proc, arguments, &regs)
}

pub fn parse_listen(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = regs.regs[0] as i64;

    if let Some(fd_data) = proc.get_fd(fd) {
        extras.insert(fd_data.name, fd_data.value.clone());
    }

    let arguments = Vec::from([
        SyscallArgument::Fd(regs.regs[0]),
        SyscallArgument::Int(regs.regs[1]),
    ]);

    SyscallEvent::new_with_extras(proc, arguments, &regs, extras)
}

pub fn parse_recv(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = regs.regs[0] as i64;
    if let Some(fd_addr) = proc.get_fd(fd) {
        extras.insert(fd_addr.name, fd_addr.value.clone());
    }

    let size = min(regs.regs[2] as usize, MAX_BUFFER_SIZE);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(regs.regs[0]),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

pub fn parse_recvfrom(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = regs.regs[0] as i64;
    let flags = regs.regs[3];
    if let Some(fd_addr) = proc.get_fd(fd) {
        extras.insert(fd_addr.name, fd_addr.value.clone());
    }
    let size = min(regs.regs[2] as usize, MAX_BUFFER_SIZE);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(regs.regs[0]),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
            SyscallArgument::Int(flags),
            SyscallArgument::Ptr(regs.regs[4]),
            SyscallArgument::Int(regs.regs[5]),
        ]),
        &regs,
        extras,
    )
}

pub fn parse_recvmsg(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = regs.regs[0] as i64;
    if let Some(fd_data) = proc.get_fd(fd) {
        extras.insert(fd_data.name, fd_data.value.clone());
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(regs.regs[0]),
            SyscallArgument::Ptr(regs.regs[1]),
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}
