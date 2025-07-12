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
use crate::parsers::syscall_parsers_file::common::{
    add_dirfd_extra, read_pathname, read_pathname_to_key,
};
use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{EXTRA_NEW_PATHNAME, EXTRA_TARGET_PATHNAME};
use crate::syscall_event::{ExtraData, SyscallEvent};
use crate::trace_process::TraceProcess;
use std::collections::HashMap;

#[cfg(target_arch = "x86_64")]
// int link(const char *oldpath, const char *newpath);
pub(crate) fn parse_link(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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

//  int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
pub(crate) fn parse_linkat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let old_dirfd = regs.regs[0];
    add_dirfd_extra(proc, old_dirfd as i64, &mut extras);

    let new_dirfd = regs.regs[1];
    add_dirfd_extra(proc, new_dirfd as i64, &mut extras);

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
            SyscallArgument::Int(flags),
        ]),
        &regs,
        extras,
    )
}

#[cfg(target_arch = "x86_64")]
// int symlink(const char *target, const char *linkpath);
pub(crate) fn parse_symlink(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let (_, target_pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);
    let (_, new_pathname_arg) =
        read_pathname_to_key(proc, &regs, 1, EXTRA_TARGET_PATHNAME, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([target_pathname_arg, new_pathname_arg]),
        &regs,
        extras,
    )
}

// int symlinkat(const char *target, int newdirfd, const char *linkpath);
pub(crate) fn parse_symlinkat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();

    let (_, target_pathname_arg) =
        read_pathname_to_key(proc, &regs, 0, EXTRA_TARGET_PATHNAME, &mut extras);

    let new_dirfd = regs.regs[1];
    add_dirfd_extra(proc, new_dirfd as i64, &mut extras);

    let (_, new_pathname_arg) = read_pathname(proc, &regs, 2, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            target_pathname_arg,
            SyscallArgument::DirFd(new_dirfd),
            new_pathname_arg,
        ]),
        &regs,
        extras,
    )
}
