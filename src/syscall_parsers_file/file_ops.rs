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

use crate::{
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_event::{ExtraData, SyscallEvent},
    syscall_parsers_file::common::{add_dirfd_extra, add_fd_filepath, read_pathname},
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
