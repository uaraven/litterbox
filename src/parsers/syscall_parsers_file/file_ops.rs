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
/*
 * This module contains parsers for file operations syscalls other than read/write.
 */

use std::collections::HashMap;


use crate::parsers::syscall_parsers_file::common::{
    add_dirfd_extra, add_fd_filepath, read_pathname, read_pathname_to_key,
};
use crate::parsers::syscall_parsers_file::fd_utils::is_fdcwd;
use crate::syscall_common::{EXTRA_NEW_DIRFD, EXTRA_NEW_PATHNAME};
use crate::{
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_event::{ExtraData, SyscallEvent},
    trace_process::TraceProcess,
};

#[cfg(target_arch = "x86_64")]
// not supported on aarch64
// int stat(const char *restrict pathname, struct stat *restrict statbuf);
// int lstat(const char *restrict pathname, struct stat *restrict statbuf);
pub(crate) fn parse_stat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let (_, pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::Ptr(regs.regs[1])]),
        &regs,
        extras,
    )
}

// int fstat(int fd, struct stat *statbuf);
pub(crate) fn parse_fstat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([SyscallArgument::Fd(fd), SyscallArgument::Ptr(regs.regs[1])]),
        &regs,
        extras,
    )
}

pub(crate) fn parse_fstatat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let dirfd = regs.regs[0];
    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);
    let flags = regs.regs[3];

    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Int(dirfd),
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[2]),
            SyscallArgument::Int(flags),
        ]),
        &regs,
        extras,
    )
}

#[cfg(target_arch = "x86_64")]
// int chmod(const char *path, mode_t mode);
pub(crate) fn parse_chmod(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    use crate::syscall_common::read_cstring;
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
    };
    if !is_entry {
        proc.set_cwd(pathname.clone());
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::FileMode(regs.regs[1])]),
        &regs,
        Default::default(),
    )
}

// int fchmod(int fd, mode_t mode);
pub(crate) fn parse_fchmod(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::FileMode(regs.regs[1]),
        ]),
        &regs,
        extras,
    )
}

// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
pub(crate) fn parse_fchmodat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let dirfd = regs.regs[0];
    let mode = regs.regs[2];
    let mut extra: ExtraData = HashMap::new();
    let pathname_arg = read_pathname(proc, &regs, 1, &mut extra).1;
    add_dirfd_extra(proc, dirfd as i64, &mut extra);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(dirfd),
            pathname_arg,
            SyscallArgument::FileMode(mode),
        ]),
        &regs,
        extra,
    )
}

#[cfg(target_arch = "x86_64")]
// int chown(const char *pathname, uid_t owner, gid_t group);
// int lchown(const char *pathname, uid_t owner, gid_t group);
pub(crate) fn parse_chown(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras = HashMap::<&str, String>::new();
    let (_, pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            pathname_arg,
            SyscallArgument::Int(regs.regs[1]),
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

// int fchown(int fd, uid_t owner, gid_t group);
pub(crate) fn parse_fchown(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras = HashMap::<&str, String>::new();
    let fd = add_fd_filepath(proc, &regs, &mut extras);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            SyscallArgument::Int(regs.regs[1]),
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
pub(crate) fn parse_fchownat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras = HashMap::<&str, String>::new();
    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(dirfd),
            pathname_arg,
            SyscallArgument::Int(regs.regs[1]),
            SyscallArgument::Int(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
        extras,
    )
}

#[cfg(target_arch = "x86_64")]
// int rename(const char *oldpath, const char *newpath);
pub(crate) fn parse_rename(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let (_, old_pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);
    let (_, new_pathname_arg) =
        read_pathname_to_key(proc, &regs, 1, EXTRA_NEW_PATHNAME, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([old_pathname_arg, new_pathname_arg]),
        &regs,
        extras,
    )
}

// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
pub(crate) fn parse_renameat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let old_dirfd = regs.regs[0];
    add_dirfd_extra(proc, old_dirfd as i64, &mut extras);

    let new_dirfd = regs.regs[1];
    if !is_fdcwd(new_dirfd as i32) && let Some(procfd) = proc.get_fd(new_dirfd as i64) {
        extras.insert(EXTRA_NEW_DIRFD, procfd.value.clone());        
    }
    

    let (_, old_pathname_arg) = read_pathname(proc, &regs, 2, &mut extras);
    let (_, new_pathname_arg) =
        read_pathname_to_key(proc, &regs, 3, EXTRA_NEW_PATHNAME, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(old_dirfd),
            SyscallArgument::DirFd(new_dirfd),
            old_pathname_arg,
            new_pathname_arg,
        ]),
        &regs,
        extras,
    )
}

// int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
pub(crate) fn parse_renameat2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let old_dirfd = regs.regs[0];
    add_dirfd_extra(proc, old_dirfd as i64, &mut extras);

    let new_dirfd = regs.regs[1];
    if !is_fdcwd(new_dirfd as i32) && let Some(procfd) = proc.get_fd(new_dirfd as i64) {
        extras.insert(EXTRA_NEW_DIRFD, procfd.value.clone());        
    }

    let (_, old_pathname_arg) = read_pathname(proc, &regs, 2, &mut extras);
    let (_, new_pathname_arg) =
        read_pathname_to_key(proc, &regs, 3, EXTRA_NEW_PATHNAME, &mut extras);

    let flags = regs.regs[4];

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(old_dirfd),
            SyscallArgument::DirFd(new_dirfd),
            old_pathname_arg,
            new_pathname_arg,
            SyscallArgument::RenameFlags(flags),
        ]),
        &regs,
        extras,
    )
}
