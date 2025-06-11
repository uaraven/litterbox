use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::flags::{clone_flags_to_str, dir_fd_to_str, open_flags_to_str};

#[derive(Debug, Clone, serde::Serialize)]
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
            SyscallArgument::IpV4Address { addr, port } => write!(f, "\"{}:{}\"", addr, port),
            SyscallArgument::IpV6Address { addr, port } => write!(f, "\"[{}]:{}\"", addr, port),
            SyscallArgument::OpenFlags(flags) => write!(f, "{}", open_flags_to_str(*flags)),
            SyscallArgument::DirFd(fd) => write!(f, "{}", dir_fd_to_str(*fd)),
            SyscallArgument::Raw(raw) => write!(f, "0x{:x}", raw),
            SyscallArgument::CloneFlags(flags) => write!(f, "{}", clone_flags_to_str(*flags)),
        }
    }
}
