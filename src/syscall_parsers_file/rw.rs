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

use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{EXTRA_PATHNAME, MAX_BUFFER_SIZE, read_buffer, read_cstring};
use crate::syscall_parsers_file::common::add_fd_filepath;
use crate::trace_process::TraceProcess;
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

use super::common::add_dirfd_extra;

// ssize_t write(int fd, const void buf[.count], size_t count);
pub(crate) fn parse_write(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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

// ssize_t read(int fd, void buf[.count], size_t count);
pub(crate) fn parse_read(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, is_entry, &mut extras);
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

#[cfg(target_arch = "x86_64")]
// int chmod(const char *path, mode_t mode);
pub(crate) fn parse_chmod(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
    };
    if !is_entry {
        proc.set_cwd(pathname.clone());
    }
    SyscallEvent::new_with_extras(proc, Vec::from([pathname_arg]), &regs, Default::default())
}

// int fchmod(int fd, mode_t mode);
pub(crate) fn parse_fchmod(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, is_entry, &mut extras);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([SyscallArgument::Fd(fd), SyscallArgument::Int(regs.regs[1])]),
        &regs,
        extras,
    )
}

// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
pub(crate) fn parse_fchmodat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };
    let dirfd = regs.regs[0];
    let flags = regs.regs[2];
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        if !is_entry {
            proc.add_fd(
                regs.return_value as i64,
                EXTRA_PATHNAME,
                pathname.clone(),
                flags,
            );
        }
        extra.insert(EXTRA_PATHNAME, pathname.clone());
    }
    add_dirfd_extra(proc, dirfd as i64, &mut extra);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(dirfd),
            pathname_arg,
            SyscallArgument::Int(flags),
        ]),
        &regs,
        extra,
    )
}

// int chdir(const char *path);
pub(crate) fn parse_chdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };
    if !is_entry && regs.return_value == 0 {
        proc.set_cwd(pathname.clone());
    }
    SyscallEvent::new_with_extras(proc, Vec::from([pathname_arg]), &regs, Default::default())
}

// int fchdir(int fd);
pub(crate) fn parse_fchdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let fd = regs.regs[0] as i64;
    let mut extras = HashMap::<&str, String>::new();
    if let Some(fd_data) = proc.get_fd(fd) {
        if !is_entry && fd > 0 && regs.return_value == 0 {
            proc.set_cwd(fd_data.value.clone());
        }
    }
    if let Some(fd_data) = proc.get_fd(fd) {
        extras.insert(fd_data.name, fd_data.value.clone());
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([SyscallArgument::DirFd(regs.regs[0])]),
        &regs,
        extras,
    )
}

// TODO:
// ssize_t pread(int fd, void buf[.count], size_t count, off_t offset);
// ssize_t pwrite(int fd, const void buf[.count], size_t count, off_t offset);

//ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
//ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);

// ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
// ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);

// int ioctl(int fd, unsigned long op, ...);  /* glibc, BSD */
// int ioctl(int fd, int op, ...);            /* musl, other UNIX */
// ssize_t copy_file_range(int fd_in, off_t *_Nullable off_in, int fd_out, off_t *_Nullable off_out, size_t size, unsigned int flags);
