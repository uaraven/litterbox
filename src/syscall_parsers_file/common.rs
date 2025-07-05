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
use crate::{
    fd_utils::is_fdcwd,
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_common::{EXTRA_CWD, EXTRA_DIRFD, EXTRA_PATHNAME, read_cstring},
    syscall_event::ExtraData,
    trace_process::TraceProcess,
};

pub(crate) fn read_pathname(
    proc: &mut TraceProcess,
    regs: &Regs,
    pathname_reg: usize,
    extra: &mut ExtraData,
) -> (String, SyscallArgument) {
    let (pathname, pathname_arg) =
        match read_cstring(proc.get_pid(), regs.regs[pathname_reg] as usize) {
            Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
            Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
        };
    if !pathname.is_empty() {
        extra.insert(EXTRA_PATHNAME, pathname.clone());
    }
    (pathname.clone(), pathname_arg)
}

pub(crate) fn add_dirfd_extra(proc: &mut TraceProcess, dirfd: i64, extra: &mut ExtraData) {
    if is_fdcwd(dirfd as i32) {
        extra.insert(EXTRA_CWD, proc.get_cwd());
    } else if let Some(fd_data) = proc.get_fd(dirfd as i64) {
        extra.insert(EXTRA_DIRFD, fd_data.value.clone());
    }
}

pub(crate) fn add_fd_filepath(proc: &mut TraceProcess, regs: &Regs, extras: &mut ExtraData) -> u64 {
    let is_entry = proc.is_entry(regs.syscall_id);
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
    fd
}
