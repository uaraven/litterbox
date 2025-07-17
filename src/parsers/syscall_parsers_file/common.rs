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
use crate::parsers::syscall_parsers_file::fd_utils::is_fdcwd;
use crate::{
    regs::Regs,
    syscall_args::SyscallArgument,
    syscall_common::{read_cstring, EXTRA_CWD, EXTRA_DIRFD, EXTRA_PATHNAME},
    syscall_event::ExtraData,
    trace_process::TraceProcess,
};

/// Reads pathname from a syscall parameter. If c-string was successfully read, stores
/// the string in the extras with the name [EXTRA_PATHNAME]
/// Returns a tuple containing pathname as a string and as a [SyscallArgument]
pub(crate) fn read_pathname(
    proc: &mut TraceProcess,
    regs: &Regs,
    pathname_param_no: usize,
    extra: &mut ExtraData,
) -> (String, SyscallArgument) {
    read_pathname_to_key(proc, regs, pathname_param_no, EXTRA_PATHNAME, extra)
}

/// Reads pathname from a syscall parameter. If c-string was successfully read, stores
/// the string in the extras with the provided key
/// Returns a tuple containing pathname as a string and as a [SyscallArgument]
pub(crate) fn read_pathname_to_key(
    proc: &mut TraceProcess,
    regs: &Regs,
    pathname_param_no: usize,
    key: &'static str,
    extra: &mut ExtraData,
) -> (String, SyscallArgument) {
    let (pathname, pathname_arg) =
        match read_cstring(proc.get_pid(), regs.regs[pathname_param_no] as usize) {
            Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
            Err(_) => (
                "".to_string(),
                SyscallArgument::Ptr(regs.regs[pathname_param_no]),
            ),
        };
    if !pathname.is_empty() {
        extra.insert(key, pathname.clone());
    }
    (pathname.clone(), pathname_arg)
}

/// Analyzes the dirfd parameter. If it contains AT_FDCWD value, then current working directory
/// is saved as [EXTRA_CWD] extra.
/// In other case, process is searched for a filepath associated with the file descriptor in `dirfd`
/// and, if found, it is stored as [EXTRA_DIRFD]
pub(crate) fn add_dirfd_extra(proc: &mut TraceProcess, dirfd: i64, extra: &mut ExtraData) {
    if is_fdcwd(dirfd as i32) {
        extra.insert(EXTRA_CWD, proc.get_cwd());
    } else if let Some(fd_data) = proc.get_fd(dirfd as i64) {
        extra.insert(EXTRA_DIRFD, fd_data.value.clone());
    }
}

/// File descriptor value is read from syscall argument 0. If there is a filepath associated with
/// the descriptor, it is stored in extras with key [EXTRA_PATHNAME].
/// The value of the file descriptor is returned
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
