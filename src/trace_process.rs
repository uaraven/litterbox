use std::{collections::HashMap, env};

use nix::unistd::Pid;

use crate::syscall_event::{SyscallEvent, SyscallStopType};

/// A struct to hold the additional data for a file descriptor
/// This structure is populated by the syscall that creates the file descriptor
/// and is used to provide additional information about the file descriptor
/// at the point of use. For example, the filepath associated with the file descriptor
/// during `sys_open` call can be retrieved from this structure during the `sys_read` call.
#[derive(Debug, Clone)]
pub struct FdData {
    pub name: &'static str,
    pub value: String,
    pub flags: u64,
}

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

    pub fn copy_from(other: &TraceProcess, new_pid: Pid) -> Self {
        Self {
            pid: new_pid,
            cwd: other.cwd.clone(),
            last_syscall: SyscallEvent::fake_event(),
            expected_stop_type: SyscallStopType::Enter,
            //TODO: Clean the fd map if FD_CLOEXEC or O_CLOEXEC are set when the new process is created
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
}
