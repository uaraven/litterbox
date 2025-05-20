use std::collections::HashMap;

use nix::libc::open_how;

use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{EXTRA_PATHNAME, read_buffer_as_type, read_cstring};
use crate::syscall_parsers_file::common::add_dirfd_extra;
use crate::trace_process::TraceProcess;
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

// int creat(const char *pathname, mode_t mode);
pub(crate) fn parse_creat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
    };
    let mode = regs.regs[1];
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        proc.add_fd(
            regs.return_value as i64,
            EXTRA_PATHNAME,
            pathname.clone(),
            mode,
        );
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::Int(mode)]),
        &regs,
        extra,
    )
}

//  int open(const char *pathname, int flags, ... /* mode_t mode */ );
pub(crate) fn parse_open(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);

    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[0] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[0])),
    };

    let flags = regs.regs[1];
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
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([pathname_arg, SyscallArgument::OpenFlags(flags)]),
        &regs,
        extra,
    )
}

///  int openat(int dirfd, const char *pathname, int flags, . . /* mode_t mode */ );
pub(crate) fn parse_openat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    add_dirfd_extra(proc, dirfd as i64, &mut extra);

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

/// long syscall(SYS_openat2, int dirfd, const char *pathname, struct open_how *how, size_t size);
pub(crate) fn parse_openat2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };
    let dirfd = regs.regs[0];
    let open_flags = match read_buffer_as_type::<open_how>(proc.get_pid(), regs.regs[2] as usize) {
        Ok(buf) => buf.flags,
        Err(_) => 0,
    };
    let mut extra: ExtraData = HashMap::new();
    if !pathname.is_empty() {
        if !is_entry {
            proc.add_fd(
                regs.return_value as i64,
                EXTRA_PATHNAME,
                pathname.clone(),
                open_flags,
            );
        }
        extra.insert(EXTRA_PATHNAME, pathname);
    }
    add_dirfd_extra(proc, dirfd as i64, &mut extra);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::DirFd(regs.regs[0]),
            pathname_arg,
            SyscallArgument::Ptr(regs.regs[2]),
            SyscallArgument::Int(regs.regs[3]),
        ]),
        &regs,
        extra,
    )
}

// int close(int fd);
pub(crate) fn parse_close(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    if is_entry {
        proc.remove_fd(regs.regs[0] as i64);
    }
    SyscallEvent::new(proc, Vec::from([SyscallArgument::Fd(regs.regs[0])]), &regs)
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
