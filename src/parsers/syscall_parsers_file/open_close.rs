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
use nix::fcntl::OFlag;
use nix::libc::{self, open_how};
use std::collections::HashMap;

use crate::flags::open_flags_to_str;
use crate::parsers::syscall_parsers_file::common::{add_dirfd_extra, read_pathname};
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{read_buffer_as_type, EXTRA_FLAGS};
use crate::syscall_event::get_abs_filepath_from_extra;
use crate::trace_process::TraceProcess;
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

// int creat(const char *pathname, mode_t mode);
pub(crate) fn parse_creat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mode = regs.regs[1];
    let mut extras: ExtraData = HashMap::new();
    let (pathname, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);
    if !pathname.is_empty() {
        proc.add_created_path(pathname.clone());
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::Int(mode)]),
        &regs,
        extras,
    )
}

//  int open(const char *pathname, int flags, ... /* mode_t mode */ );
pub(crate) fn parse_open(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let flags = regs.regs[1];
    let mut extras: ExtraData = HashMap::new();
    extras.insert(EXTRA_FLAGS, open_flags_to_str(flags));
    let (pathname, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);
    if !pathname.is_empty() {
        if (flags as i32) & libc::O_CREAT != 0 {
            proc.add_created_path(pathname.clone());
        }
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::OpenFlags(flags)]),
        &regs,
        extras,
    )
}

///  int openat(int dirfd, const char *pathname, int flags, . . /* mode_t mode */ );
pub(crate) fn parse_openat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();
    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    let flags = regs.regs[2];
    let libc_flags = OFlag::from_bits(flags as i32).unwrap_or(OFlag::empty());
    extras.insert(EXTRA_FLAGS, open_flags_to_str(flags));

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);

    if let Some(path) = get_abs_filepath_from_extra(&extras) && libc_flags.contains(OFlag::O_CREAT)  {
        proc.add_created_path(path);
    }

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(regs.regs[0]),
            pathname_arg,
            SyscallArgument::OpenFlags(flags),
        ]),
        &regs,
        extras,
    )
}

/// long syscall(SYS_openat2, int dirfd, const char *pathname, struct open_how *how, size_t size);
pub(crate) fn parse_openat2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();

    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    let open_flags = match read_buffer_as_type::<open_how>(proc.get_pid(), regs.regs[2] as usize) {
        Ok(buf) => buf.flags,
        Err(_) => 0,
    };
    extras.insert(EXTRA_FLAGS, open_flags_to_str(open_flags));
    let libc_flags = OFlag::from_bits(open_flags as i32).unwrap_or(OFlag::empty());

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);
    if let Some(path) = get_abs_filepath_from_extra(&extras) && libc_flags.contains(OFlag::O_CREAT) {
        proc.add_created_path(path);
    }

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(regs.regs[0]),
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
        extras,
    )
}

// int close(int fd);
pub(crate) fn parse_close(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    if !is_entry {
        proc.remove_fd(regs.regs[0] as i64);
    }
    SyscallEvent::new(proc, Vec::from([SyscallArgument::Fd(regs.regs[0])]), &regs)
}

pub(crate) fn parse_access(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();

    let (_, pathname_arg) = read_pathname(proc, &regs, 0, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            pathname_arg,
            SyscallArgument::Int(regs.regs[1]),
        ]),
        &regs,
        extras,
    )
}


pub(crate) fn parse_faccessat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let mut extras: ExtraData = HashMap::new();

    let dirfd = regs.regs[0];
    add_dirfd_extra(proc, dirfd as i64, &mut extras);

    let (_, pathname_arg) = read_pathname(proc, &regs, 1, &mut extras);

    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(dirfd),
            pathname_arg,
            SyscallArgument::Int(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
        extras,
    )
}