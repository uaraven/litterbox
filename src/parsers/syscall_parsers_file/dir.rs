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
    parsers::syscall_parsers_file::common::{add_dirfd_extra, read_pathname},
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_common::read_cstring,
    syscall_event::{ExtraData, SyscallEvent},
    trace_process::TraceProcess,
};

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

// int mkdir(const char *pathname, mode_t mode);
pub(crate) fn parse_mkdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let (_, pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);
    let mode = regs.regs[1];

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::FileMode(mode)]),
        &regs,
        extras,
    )
}

// int mkdirat(int dirfd, const char *pathname, mode_t mode);
pub(crate) fn parse_mkdirat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();

    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);
    let mode = regs.regs[2];

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(dirfd),
            pathname_arg,
            SyscallArgument::FileMode(mode),
        ]),
        &regs,
        extras,
    )
}
