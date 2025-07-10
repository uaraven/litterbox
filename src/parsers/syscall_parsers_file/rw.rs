/*
 * Litterbox - A sandboxing and tracing tool
 *
 * Copyright (c) 2025  Oles Voronin
 *
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this
 * program. If not, see <https://www.gnu.org/licenses/>.
 *
 */
use std::cmp::min;
use std::collections::HashMap;

use crate::parsers::syscall_parsers_file::common::add_fd_filepath;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{MAX_BUFFER_SIZE, read_buffer};
use crate::trace_process::TraceProcess;
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

// ssize_t read(int fd, void buf[.count], size_t count);
// ssize_t write(int fd, const void buf[.count], size_t count);
pub(crate) fn parse_read_write(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, &mut extras);
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

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
pub(crate) fn parse_readv_writev(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    let iovec_ptr = regs.regs[1];
    let iovcnt = regs.regs[2];
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::Ptr(iovec_ptr),
            SyscallArgument::Int(iovcnt),
        ]),
        &regs,
        extras,
    )
}

// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
pub(crate) fn parse_preadv_pwritev(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    let iovec_ptr = regs.regs[1];
    let iovcnt = regs.regs[2];
    let offset = regs.regs[3];
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::Ptr(iovec_ptr),
            SyscallArgument::Int(iovcnt),
            SyscallArgument::Int(offset),
        ]),
        &regs,
        extras,
    )
}

// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
pub(crate) fn parse_preadv2_pwritev2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    let iovec_ptr = regs.regs[1];
    let iovcnt = regs.regs[2];
    let offset = regs.regs[3];
    let flags = regs.regs[4];
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::Ptr(iovec_ptr),
            SyscallArgument::Int(iovcnt),
            SyscallArgument::Int(offset),
            SyscallArgument::Bits(flags),
        ]),
        &regs,
        extras,
    )
}

// ssize_t pread(int fd, void buf[.count], size_t count, off_t offset);
// ssize_t pwrite(int fd, const void buf[.count], size_t count, off_t offset);

pub(crate) fn parse_pread64_pwrite64(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    let buf = regs.regs[1];
    let count = regs.regs[2];
    let offset = regs.regs[3];
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::Ptr(buf),
            SyscallArgument::Int(count),
            SyscallArgument::Int(offset),
        ]),
        &regs,
        extras,
    )
}
