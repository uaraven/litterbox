use std::{collections::HashMap, env};

use nix::{libc, unistd::Pid};

use crate::syscall_event::{SyscallEvent, SyscallStopType};

/// A struct to hold the additional data for a file descriptor
/// This structure is populated by the syscall that creates the file descriptor
/// and is used to provide additional information about the file descriptor
/// at the point of use. For example, the filepath associated with the file descriptor
/// during `sys_open` call can be retrieved from this structure during the `sys_read` call.
#[derive(Debug, Clone)]
pub struct FdData {
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

#[derive(Debug, Clone)]
pub struct TraceProcess {
    pid: Pid,
    last_syscall: SyscallEvent,
    expected_stop_type: SyscallStopType,
    cwd: String,
    fd_map: HashMap<i64, FdData>,
}

impl TraceProcess {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            last_syscall: SyscallEvent::fake_event(),
            expected_stop_type: SyscallStopType::Enter,
            cwd: match env::current_dir() {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(_) => "".to_string(),
            },
            fd_map: HashMap::new(),
        }
    }

    /// Create a new TraceProcess with the same data as another TraceProcess
    /// but with a different PID. This is used when a process forks.
    pub fn clone_process(other: &TraceProcess, new_pid: Pid) -> Self {
        Self {
            pid: new_pid,
            cwd: other.cwd.clone(),
            last_syscall: SyscallEvent::fake_event(),
            expected_stop_type: SyscallStopType::Enter,
            fd_map: other.fd_map.clone(),
        }
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    // Get the last syscall event
    // If the current syscall ID is not the same as the last syscall ID, return None
    pub fn get_last_syscall(&self, current_syscall_id: u64) -> Option<&SyscallEvent> {
        if self.last_syscall.id != current_syscall_id {
            return None;
        } else {
            Some(&self.last_syscall)
        }
    }

    pub fn set_last_syscall(&mut self, syscall: &SyscallEvent) {
        self.last_syscall = syscall.clone();
    }

    pub fn add_fd(&mut self, fd: i64, name: &'static str, value: String, flags: u64) {
        self.fd_map.insert(fd, FdData { name, value, flags });
    }

    pub fn get_fd(&self, fd: i64) -> Option<&FdData> {
        self.fd_map.get(&fd)
    }

    pub fn remove_fd(&mut self, fd: i64) {
        self.fd_map.remove(&fd);
    }

    pub fn set_current_stop_type(&mut self, stop_type: SyscallStopType) {
        self.expected_stop_type = match stop_type {
            SyscallStopType::Enter => SyscallStopType::Exit,
            SyscallStopType::Exit => SyscallStopType::Enter,
        };
    }

    pub fn is_entry(&self, syscall_id: u64) -> bool {
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
    pub fn clear_closed_fds(&mut self) {
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

    pub fn set_cwd(&mut self, cwd: String) {
        self.cwd = cwd;
    }

    pub fn get_cwd(&self) -> String {
        self.cwd.clone()
    }
}
