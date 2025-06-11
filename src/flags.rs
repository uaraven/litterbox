use std::ffi::c_int;

use nix::{
    fcntl::{AtFlags, OFlag},
    libc,
};

pub(crate) fn dir_fd_to_str(fd: u64) -> String {
    let mut s: Vec<&str> = Vec::new();
    let cfd = fd as c_int;
    if cfd & libc::AT_FDCWD == libc::AT_FDCWD {
        s.push("AT_FDCWD");
    }
    let aflag = AtFlags::from_bits(fd.try_into().unwrap_or(0)).unwrap_or(AtFlags::empty());
    if aflag.contains(AtFlags::AT_EACCESS) {
        s.push("AT_EACCESS");
    }
    if aflag.contains(AtFlags::AT_SYMLINK_NOFOLLOW) {
        s.push("AT_SYMLINK_NOFOLLOW");
    }
    if aflag.contains(AtFlags::AT_REMOVEDIR) {
        s.push("AT_REMOVEDIR");
    }
    if aflag.contains(AtFlags::AT_SYMLINK_FOLLOW) {
        s.push("AT_SYMLINK_FOLLOW");
    }
    s.join("|")
}

pub(crate) fn open_flags_to_str(flags: u64) -> String {
    let mut s: Vec<&str> = Vec::new();
    let oflag = OFlag::from_bits(flags.try_into().unwrap_or(0)).unwrap_or(OFlag::empty());
    if oflag.contains(OFlag::O_RDONLY) {
        s.push("O_RDONLY");
    }
    if oflag.contains(OFlag::O_WRONLY) {
        s.push("O_WRONLY");
    }
    if oflag.contains(OFlag::O_RDWR) {
        s.push("O_RDWR");
    }
    if oflag.contains(OFlag::O_ACCMODE) {
        s.push("O_ACCMODE");
    }
    if oflag.contains(OFlag::O_APPEND) {
        s.push("O_APPEND");
    }
    if oflag.contains(OFlag::O_CREAT) {
        s.push("O_CREAT");
    }
    if oflag.contains(OFlag::O_EXCL) {
        s.push("O_EXCL");
    }
    if oflag.contains(OFlag::O_SYNC) {
        s.push("O_SYNC");
    }
    if oflag.contains(OFlag::O_TRUNC) {
        s.push("O_TRUNC");
    }
    if oflag.contains(OFlag::O_DIRECT) {
        s.push("O_DIRECT");
    }
    if oflag.contains(OFlag::O_LARGEFILE) {
        s.push("O_LARGEFILE");
    }
    if oflag.contains(OFlag::O_DIRECTORY) {
        s.push("O_DIRECTORY");
    }
    if oflag.contains(OFlag::O_NOFOLLOW) {
        s.push("O_NOFOLLOW");
    }
    if oflag.contains(OFlag::O_NOCTTY) {
        s.push("O_NOCTTY");
    }
    if oflag.contains(OFlag::O_NONBLOCK) {
        s.push("O_NONBLOCK");
    }
    if oflag.contains(OFlag::O_CLOEXEC) {
        s.push("O_CLOEXEC");
    }
    if oflag.contains(OFlag::O_TMPFILE) {
        s.push("O_TMPFILE");
    }
    s.join("|")
}

pub(crate) fn clone_flags_to_str(flags: u64) -> String {
    let mut s: Vec<&str> = Vec::new();
    let f = flags as c_int;
    if f & libc::CLONE_THREAD != 0 {
        s.push("CLONE_THREAD");
    }
    if f & libc::CLONE_UNTRACED != 0 {
        s.push("CLONE_UNTRACED");
    }
    if f & libc::CLONE_VFORK != 0 {
        s.push("CLONE_VFORK");
    }
    if f & libc::CLONE_VM != 0 {
        s.push("CLONE_VM");
    }
    if f & libc::CLONE_PTRACE != 0 {
        s.push("CLONE_PTRACE");
    }
    if f & libc::CLONE_NEWCGROUP != 0 {
        s.push("CLONE_NEWCGROUP");
    }

    let mut flags_s = s.join("|");
    flags_s.push_str(format!(" 0x{:x}", flags).as_str());
    flags_s
}
