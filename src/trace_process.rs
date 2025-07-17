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

use std::{
    collections::{HashMap, HashSet},
    env,
};

use nix::{
    libc::{self, user_regs_struct},
    unistd::Pid,
};

use crate::syscall_event::{SyscallEvent, SyscallStopType};

/// A struct to hold the additional data for a file descriptor
/// This structure is populated by the syscall that creates the file descriptor
/// and is used to provide additional information about the file descriptor
/// at the point of use. For example, the filepath associated with the file descriptor
/// during `sys_open` call can be retrieved from this structure during the `sys_read` call.
#[derive(Debug, Clone)]
pub(crate) struct FdData {
    // The name of this data. Depends on the syscall that created the fd
    // For example, `pathname` for `sys_open` syscall or `addr` for `sys_connect`
    pub name: &'static str,
    // The value associated with the fd
    pub value: String,
    // The flags which were used when opening the fd.
    pub flags: u64,
}
impl FdData {
    pub fn is_dir(&self) -> bool {
        self.flags as i32 & libc::O_PATH == libc::O_PATH
    }

    pub fn is_close_on_exec(&self) -> bool {
        self.flags as i32 & libc::O_CLOEXEC == libc::O_CLOEXEC
    }
}
pub(crate) type SetSyscallId = fn(Pid, user_regs_struct, u64) -> Result<(), nix::Error>;

#[cfg(target_arch = "x86_64")]
pub fn set_syscall_id(
    pid: Pid,
    arch_regs: user_regs_struct,
    syscall_id: u64,
) -> Result<(), nix::Error> {
    use nix::sys::ptrace;

    let mut regs = arch_regs;
    regs.orig_rax = syscall_id;
    ptrace::setregs(pid, regs)
}

/// On ARM64, we need to use different register set, NT_ARM_SYSTEM_CALL,
/// to set the syscall ID. Usual ptrace::setregs will not work.
#[cfg(target_arch = "aarch64")]
pub fn set_syscall_id(
    pid: Pid,
    _arch_regs: user_regs_struct,
    new_syscall_id: u64,
) -> Result<(), nix::Error> {
    const PTRACE_SETREGSET: usize = 0x4205;
    const NT_ARM_SYSTEM_CALL: usize = 0x404;

    let regs = libc::iovec {
        iov_base: &new_syscall_id as *const _ as *mut c_void,
        iov_len: std::mem::size_of_val(&new_syscall_id),
    };
    let res = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET as _,
            libc::pid_t::from(pid.as_raw()),
            NT_ARM_SYSTEM_CALL,
            &regs as *const _ as *const c_void,
        )
    };
    Errno::result(res)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct TraceProcess {
    pid: Pid,
    last_syscall: SyscallEvent,
    expected_stop_type: SyscallStopType,
    cwd: String,
    fd_map: HashMap<i64, FdData>,
    created_paths: HashSet<String>,
    pub set_syscall_id: SetSyscallId,
}

impl TraceProcess {
    pub(crate) fn new(pid: Pid) -> Self {
        Self {
            pid,
            last_syscall: SyscallEvent::empty_event(),
            expected_stop_type: SyscallStopType::Enter,
            cwd: match env::current_dir() {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(_) => "".to_string(),
            },
            fd_map: HashMap::new(),
            created_paths: HashSet::new(),
            set_syscall_id: set_syscall_id,
        }
    }

    /// Create a new TraceProcess with the same data as another TraceProcess
    /// but with a different PID. This is used when a process forks.
    pub(crate) fn clone_process(other: &TraceProcess, new_pid: Pid) -> Self {
        Self {
            pid: new_pid,
            cwd: other.cwd.clone(),
            last_syscall: SyscallEvent::empty_event(),
            expected_stop_type: SyscallStopType::Enter,
            fd_map: other.fd_map.clone(),
            created_paths: other.created_paths.clone(),
            set_syscall_id: other.set_syscall_id,
        }
    }

    pub(crate) fn get_pid(&self) -> Pid {
        self.pid
    }

    // Get the last syscall event
    // If the current syscall ID is not the same as the last syscall ID, return None
    pub(crate) fn get_last_syscall(&self, current_syscall_id: u64) -> Option<&SyscallEvent> {
        if self.last_syscall.id != current_syscall_id {
            None
        } else {
            Some(&self.last_syscall)
        }
    }

    pub(crate) fn get_previous_syscall(&self) -> SyscallEvent {
        self.last_syscall.clone()
    }

    pub(crate) fn set_last_syscall(&mut self, syscall: &SyscallEvent) {
        self.last_syscall = syscall.clone();
    }

    pub(crate) fn add_fd(&mut self, fd: i64, name: &'static str, value: String, flags: u64) {
        self.fd_map.insert(fd, FdData { name, value, flags });
    }
    pub(crate) fn get_fd(&self, fd: i64) -> Option<&FdData> {
        self.fd_map.get(&fd)
    }

    pub(crate) fn remove_fd(&mut self, fd: i64) {
        self.fd_map.remove(&fd);
    }

    pub(crate) fn add_created_path(&mut self, path: String) {
        self.created_paths.insert(path);
    }

    pub(crate) fn is_created_by_process(&self, path: &str) -> bool {
        self.created_paths.contains(path)
    }

    pub(crate) fn remove_created_path(&mut self, path: &String) {
        self.created_paths.remove(path);
    }

    pub(crate) fn set_current_stop_type(&mut self, stop_type: SyscallStopType) {
        self.expected_stop_type = match stop_type {
            SyscallStopType::Enter => SyscallStopType::Exit,
            SyscallStopType::Exit => SyscallStopType::Enter,
        };
    }

    pub(crate) fn is_entry(&self, syscall_id: u64) -> bool {
        match self.expected_stop_type {
            SyscallStopType::Enter => true,
            SyscallStopType::Exit => {
                if self.last_syscall.id == syscall_id {
                    false
                } else {
                    // if we thought that previous syscall-stop was on entry and now we see different syscall id
                    // that means that the previous stop was actually on exit and now is on entry
                    true
                }
            }
        }
    }

    /// Deletes stored info for the file descriptors that are marked as close-on-exec
    pub(crate) fn clear_closed_fds(&mut self) {
        let mut fds_to_remove = Vec::new();
        for (fd, fd_data) in &self.fd_map {
            if fd_data.is_close_on_exec() {
                fds_to_remove.push(*fd);
            }
        }
        for fd in fds_to_remove {
            self.remove_fd(fd);
        }
    }

    pub(crate) fn set_cwd(&mut self, cwd: String) {
        self.cwd = cwd;
    }

    pub(crate) fn get_cwd(&self) -> String {
        self.cwd.clone()
    }
}
