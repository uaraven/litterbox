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

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::flags::{clone_flags_to_str, dir_fd_to_str, file_mode_to_str, open_flags_to_str};

#[derive(Debug, Clone, serde::Serialize)]
pub enum SyscallArgument {
    Int(u64),
    Fd(u64),
    Ptr(u64),
    String(String),
    Bytes(Vec<u8>),
    Bits(u64),
    UnixAddress { addr: String },
    IpV4Address { addr: Ipv4Addr, port: u16 },
    IpV6Address { addr: Ipv6Addr, port: u16 },
    OpenFlags(u64),
    CloneFlags(u64),
    FileMode(u64),
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
            SyscallArgument::Bits(bits) => write!(f, "0b{:b}", bits),
            SyscallArgument::UnixAddress { addr } => write!(f, "{}", addr),
            SyscallArgument::IpV4Address { addr, port } => write!(f, "\"{}:{}\"", addr, port),
            SyscallArgument::IpV6Address { addr, port } => write!(f, "\"[{}]:{}\"", addr, port),
            SyscallArgument::OpenFlags(flags) => write!(f, "{}", open_flags_to_str(*flags)),
            SyscallArgument::DirFd(fd) => write!(f, "{}", dir_fd_to_str(*fd)),
            SyscallArgument::Raw(raw) => write!(f, "0x{:x}", raw),
            SyscallArgument::CloneFlags(flags) => write!(f, "{}", clone_flags_to_str(*flags)),
            SyscallArgument::FileMode(mode) => write!(f, "{}", file_mode_to_str(*mode)),
        }
    }
}
