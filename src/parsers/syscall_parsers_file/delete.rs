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
use std::collections::HashMap;

use crate::{
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_common::{EXTRA_PATHNAME, read_cstring},
    syscall_event::{ExtraData, SyscallEvent},
    trace_process::TraceProcess,
};

use super::common::{add_dirfd_extra, read_pathname};

#[cfg(target_arch = "x86_64")]
// int unlink(const char *pathname);
pub(crate) fn parse_unlink_rmdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extra: ExtraData = HashMap::new();

    let (_, pathname_arg) = read_pathname(proc, &regs, 0, &mut extra);

    let flags = regs.regs[1];
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::OpenFlags(flags)]),
        &regs,
        Default::default(),
    )
}

// int unlinkat(int dirfd, const char *pathname, int flags);
pub(crate) fn parse_unlinkat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extra: ExtraData = HashMap::new();

    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extra);

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extra);

    let flags = regs.regs[2];

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
