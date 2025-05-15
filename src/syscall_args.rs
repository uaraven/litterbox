use nix::fcntl::{AtFlags, OFlag};
use nix::libc;
use std::ffi::c_int;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum SyscallArgument {
    Int(u64),
    Fd(u64),
    Ptr(u64),
    String(String),
    Bytes(Vec<u8>),
    UnixAddress { addr: String },
    IpV4Address { addr: Ipv4Addr, port: u16 },
    IpV6Address { addr: Ipv6Addr, port: u16 },
    OpenFlags(u64),
    CloneFlags(u64),
    DirFd(u64),
    Raw(u64),
}

impl fmt::Display for SyscallArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallArgument::Int(i) => write!(f, "{}", i),
            SyscallArgument::Fd(fd) => write!(f, "{}", fd),
            SyscallArgument::Ptr(p) => write!(f, "0x{:x}", p),
            SyscallArgument::String(s) => write!(f, "\"{}\"", s),
            SyscallArgument::Bytes(b) => {
                let hex_str = String::from_utf8(b.to_vec())
                    .unwrap_or(
                        b.iter()
                            .map(|byte| format!("\\{:02x}", byte))
                            .collect::<String>(),
                    )
                    .replace("\n", "\\n");
                write!(f, "'{}...'", hex_str)
            }
            SyscallArgument::UnixAddress { addr } => write!(f, "{}", addr),
            SyscallArgument::IpV4Address { addr, port } => write!(f, "{}:{}", addr, port),
            SyscallArgument::IpV6Address { addr, port } => write!(f, "[{}]:{}", addr, port),
            SyscallArgument::OpenFlags(flags) => write!(f, "{}", open_flags_to_str(*flags)),
            SyscallArgument::DirFd(fd) => write!(f, "{}", dir_fd_to_str(*fd)),
            SyscallArgument::Raw(raw) => write!(f, "0x{:x}", raw),
            SyscallArgument::CloneFlags(flags) => write!(f, "{}", clone_flags_to_str(*flags)),
        }
    }
}

fn dir_fd_to_str(fd: u64) -> String {
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

fn open_flags_to_str(flags: u64) -> String {
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

fn clone_flags_to_str(flags: u64) -> String {
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
