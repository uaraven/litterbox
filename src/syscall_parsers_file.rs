use std::cmp::min;
use std::collections::HashMap;

use nix::libc::open_how;

use crate::fd_utils::is_fdcwd;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{
    EXTRA_CWD, EXTRA_DIRFD, EXTRA_PATHNAME, MAX_BUFFER_SIZE, read_buffer, read_buffer_as_type,
    read_cstring,
};
use crate::trace_process::TraceProcess;
use crate::{regs::Regs, syscall_event::ExtraData, syscall_event::SyscallEvent};

fn add_dirfd_extra(proc: &mut TraceProcess, dirfd: i64, extra: &mut ExtraData) {
    if is_fdcwd(dirfd as i32) {
        extra.insert(EXTRA_CWD, proc.get_cwd());
    } else if let Some(fd_data) = proc.get_fd(dirfd as i64) {
        extra.insert(EXTRA_DIRFD, fd_data.value.clone());
    }
}

fn add_fd_filepath(
    proc: &mut TraceProcess,
    regs: &Regs,
    is_entry: bool,
    extras: &mut ExtraData,
) -> u64 {
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

//  int open(const char *pathname, int flags, ... /* mode_t mode */ );
pub fn parse_open(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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
pub fn parse_openat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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
pub fn parse_openat2(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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
pub fn parse_close(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    if is_entry {
        proc.remove_fd(regs.regs[0] as i64);
    }
    SyscallEvent::new(proc, Vec::from([SyscallArgument::Fd(regs.regs[0])]), &regs)
}

// int creat(const char *pathname, mode_t mode);
pub fn parse_creat(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
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

// ssize_t write(int fd, const void buf[.count], size_t count);
pub fn parse_write(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();

    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
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
    let read_size = min(MAX_BUFFER_SIZE, regs.regs[2] as usize);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, read_size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

// ssize_t read(int fd, void buf[.count], size_t count);
pub fn parse_read(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, is_entry, &mut extras);
    let read_size = min(MAX_BUFFER_SIZE, regs.regs[2] as usize);
    let buffer_arg = match read_buffer(proc.get_pid(), regs.regs[1] as usize, read_size) {
        Ok(buffer) => SyscallArgument::Bytes(buffer),
        Err(_) => SyscallArgument::Ptr(regs.regs[1]),
    };
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([
            SyscallArgument::Fd(fd),
            buffer_arg,
            SyscallArgument::Int(regs.regs[2]),
        ]),
        &regs,
        extras,
    )
}

pub fn parse_fchmod(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let mut extras: ExtraData = HashMap::new();
    // on arm64, the fd in regs[0] is rewritten with the return value on the exit from syscall
    // so we need to use the fd from the entry event
    let fd = add_fd_filepath(proc, &regs, is_entry, &mut extras);
    SyscallEvent::new_with_extras(
        proc,
        Vec::from([SyscallArgument::Fd(fd), SyscallArgument::Int(regs.regs[1])]),
        &regs,
        extras,
    )
}

pub fn parse_chdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let (pathname, pathname_arg) = match read_cstring(proc.get_pid(), regs.regs[1] as usize) {
        Ok(pathname) => (pathname.clone(), SyscallArgument::String(pathname)),
        Err(_) => ("".to_string(), SyscallArgument::Ptr(regs.regs[1])),
    };
    if !is_entry {
        proc.set_cwd(pathname.clone());
    }
    SyscallEvent::new_with_extras(proc, Vec::from([pathname_arg]), &regs, Default::default())
}

pub fn parse_fchdir(proc: &mut TraceProcess, regs: Regs) -> SyscallEvent {
    let is_entry = proc.is_entry(regs.syscall_id);
    let fd = regs.regs[0] as i64;
    let mut extras = HashMap::<&str, String>::new();
    if let Some(fd_data) = proc.get_fd(fd) {
        if !is_entry && fd > 0 {
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
