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

use crate::parsers::syscall_parsers_file::delete::parse_unlinkat;
use crate::parsers::syscall_parsers_file::dir::{parse_chdir, parse_fchdir, parse_mkdirat};
use crate::parsers::syscall_parsers_file::open_close::{
    parse_close, parse_faccessat, parse_openat, parse_openat2,
};
use crate::parsers::syscall_parsers_file::rw::{
    parse_pread64_pwrite64, parse_preadv_pwritev, parse_preadv2_pwritev2, parse_read_write,
    parse_readv_writev,
};
use crate::parsers::syscall_parsers_process::{
    parse_clone, parse_clone3, parse_execve, parse_execveat,
};
use crate::parsers::syscall_parsers_socket::{
    parse_bind, parse_connect, parse_listen, parse_recvfrom, parse_recvmsg,
};
use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::SyscallParserFn;
use crate::syscall_event::SyscallEvent;

use crate::trace_process::TraceProcess;

use crate::parsers::syscall_parsers_file::file_ops::{
    parse_fchmod, parse_fchmodat, parse_fchown, parse_fchownat, parse_fstat, parse_fstatat,
    parse_renameat, parse_renameat2,
};
use crate::parsers::syscall_parsers_file::links::{parse_linkat, parse_symlinkat};
use std::ffi::c_long;
use syscall_numbers::*;

// const E_NO_SYS: u64 = (-(38i64)) as u64;
#[cfg(target_arch = "aarch64")]
pub(crate) fn syscall_parser(id: u64) -> SyscallParserFn {
    let cid: c_long = id as i64;
    if cid < 0 {
        return parse_default;
    }
    match cid {
        aarch64::SYS_openat => parse_openat,
        aarch64::SYS_openat2 => parse_openat2,
        aarch64::SYS_close => parse_close,
        aarch64::SYS_write => parse_read_write,
        aarch64::SYS_writev => parse_readv_writev,
        aarch64::SYS_pwritev => parse_preadv_pwritev,
        aarch64::SYS_pwritev2 => parse_preadv2_pwritev2,
        aarch64::SYS_pwrite64 => parse_pread64_pwrite64,
        aarch64::SYS_read => parse_read_write,
        aarch64::SYS_readv => parse_readv_writev,
        aarch64::SYS_preadv => parse_preadv_pwritev,
        aarch64::SYS_preadv2 => parse_preadv2_pwritev2,
        aarch64::SYS_pread64 => parse_pread64_pwrite64,
        aarch64::SYS_faccessat | aarch64::SYS_faccessat2 => parse_faccessat,
        aarch64::SYS_fstat => parse_fstat,
        aarch64::SYS_newfstatat => parse_fstatat,
        aarch64::SYS_fchmod => parse_fchmod,
        aarch64::SYS_fchmodat => parse_fchmodat,
        aarch64::SYS_fchown => parse_fchown,
        aarch64::SYS_fchownat => parse_fchownat,
        aarch64::SYS_chdir => parse_chdir,
        aarch64::SYS_fchdir => parse_fchdir,
        aarch64::SYS_mkdirat => parse_mkdirat,
        aarch64::SYS_renameat => parse_renameat,
        aarch64::SYS_renameat2 => parse_renameat2,
        aarch64::SYS_unlinkat => parse_unlinkat,
        aarch64::SYS_linkat => parse_linkat,
        aarch64::SYS_symlinkat => parse_symlinkat,
        aarch64::SYS_clone => parse_clone,
        aarch64::SYS_clone3 => parse_clone3,
        aarch64::SYS_execve => parse_execve,
        aarch64::SYS_execveat => parse_execveat,
        aarch64::SYS_connect => parse_connect,
        aarch64::SYS_bind => parse_bind,
        aarch64::SYS_listen => parse_listen,
        aarch64::SYS_recvfrom => parse_recvfrom,
        aarch64::SYS_recvmsg => parse_recvmsg,
        _ => parse_default,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn syscall_parser(id: u64) -> SyscallParserFn {
    use crate::parsers::syscall_parsers_file::delete::parse_unlink_rmdir;
    use crate::parsers::syscall_parsers_file::dir::parse_mkdir;
    use crate::parsers::syscall_parsers_file::file_ops::{parse_chown, parse_rename, parse_stat};
    use crate::parsers::syscall_parsers_file::links::{parse_link, parse_symlink};
    use crate::parsers::syscall_parsers_file::open_close::{parse_access, parse_creat, parse_open};

    let cid: c_long = id as i64;
    if cid < 0 {
        return parse_default;
    }
    match cid {
        x86_64::SYS_creat => parse_creat,
        x86_64::SYS_open => parse_open,
        x86_64::SYS_openat => parse_openat,
        x86_64::SYS_openat2 => parse_openat2,
        x86_64::SYS_close => parse_close,
        x86_64::SYS_write => parse_read_write,
        x86_64::SYS_writev => parse_readv_writev,
        x86_64::SYS_pwritev => parse_preadv_pwritev,
        x86_64::SYS_pwritev2 => parse_preadv2_pwritev2,
        x86_64::SYS_pwrite64 => parse_pread64_pwrite64,
        x86_64::SYS_read => parse_read_write,
        x86_64::SYS_readv => parse_readv_writev,
        x86_64::SYS_preadv => parse_preadv_pwritev,
        x86_64::SYS_preadv2 => parse_preadv2_pwritev2,
        x86_64::SYS_pread64 => parse_pread64_pwrite64,
        x86_64::SYS_access => parse_access,
        x86_64::SYS_faccessat | x86_64::SYS_faccessat2 => parse_faccessat,
        x86_64::SYS_chmod => parse_fchmod,
        x86_64::SYS_fchmod => parse_fchmod,
        x86_64::SYS_fchmodat => parse_fchmodat,
        x86_64::SYS_chown | x86_64::SYS_lchown => parse_chown,
        x86_64::SYS_fchown => parse_fchown,
        x86_64::SYS_fchownat => parse_fchownat,
        x86_64::SYS_chdir => parse_chdir,
        x86_64::SYS_fchdir => parse_fchdir,
        x86_64::SYS_mkdir => parse_mkdir,
        x86_64::SYS_mkdirat => parse_mkdirat,
        x86_64::SYS_rename => parse_rename,
        x86_64::SYS_renameat => parse_renameat,
        x86_64::SYS_renameat2 => parse_renameat2,
        x86_64::SYS_stat | x86_64::SYS_lstat => parse_stat,
        x86_64::SYS_fstat => parse_fstat,
        x86_64::SYS_newfstatat => parse_fstatat,
        x86_64::SYS_unlink | x86_64::SYS_rmdir => parse_unlink_rmdir,
        x86_64::SYS_unlinkat => parse_unlinkat,
        x86_64::SYS_link => parse_link,
        x86_64::SYS_linkat => parse_linkat,
        x86_64::SYS_symlink => parse_symlink,
        x86_64::SYS_symlinkat => parse_symlinkat,
        x86_64::SYS_clone => parse_clone,
        x86_64::SYS_clone3 => parse_clone3,
        x86_64::SYS_execve => parse_execve,
        x86_64::SYS_execveat => parse_execveat,
        x86_64::SYS_connect => parse_connect,
        x86_64::SYS_bind => parse_bind,
        x86_64::SYS_listen => parse_listen,
        x86_64::SYS_recvfrom => parse_recvfrom,
        x86_64::SYS_recvmsg => parse_recvmsg,
        _ => parse_default,
    }
}

fn parse_default(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    SyscallEvent::new(
        proc,
        Vec::from([
            SyscallArgument::Raw(regs.regs[0]),
            SyscallArgument::Raw(regs.regs[1]),
            SyscallArgument::Raw(regs.regs[2]),
            SyscallArgument::Raw(regs.regs[3]),
            SyscallArgument::Raw(regs.regs[4]),
            SyscallArgument::Raw(regs.regs[5]),
        ]),
        &regs,
    )
}
