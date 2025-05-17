use std::collections::HashSet;

use regex::Regex;
use serde::Serialize;
use syscall_numbers::native;

use crate::{
    syscall_args::SyscallArgument,
    syscall_common::{EXTRA_ADDR, EXTRA_PATHNAME},
    syscall_event::SyscallEvent,
    syscall_ids::{SYS_OPEN, SYS_RMDIR},
};

const UNPICKLER: &str = "unpickler.py";

const DIRS_SAFE_TO_READ: [&'static str; 8] = [
    r"^/tmp.*$",
    r"^/var/tmp.*$",
    r"^/dev/shm.*$",
    r"^/run.*$",
    r"^/var.*$",
    r"^/lib.*$",
    r"^/usr/lib.*$",
    r"^/usr/local.*$",
];

const DIRS_UNSAFE_TO_READ: [&'static str; 3] = ["^/etc/shadow$", r"^.*\.aws/.*$", r"^.*\.ssh/.*$"];

const VERIFY_SYSCALLS: [i64; 12] = [
    SYS_OPEN,
    SYS_RMDIR,
    native::SYS_openat,
    native::SYS_read,
    native::SYS_write,
    native::SYS_unlinkat,
    native::SYS_renameat,
    native::SYS_renameat2,
    native::SYS_connect,
    native::SYS_accept,
    native::SYS_execve,
    native::SYS_execveat,
];

#[derive(Serialize, Clone, Debug)]
pub enum ScanSafety {
    Safe,
    Suspicious,
    Unsafe,
}

#[derive(Serialize, Clone, Debug)]
pub enum AccessType {
    Other,
    FileSystemRead,
    FileSystemWrite,
    Network,
    Process,
}
#[derive(Serialize, Clone, Debug)]
pub struct ScanEvent {
    pub pid: u64,
    pub syscall_name: String,
    pub access_type: AccessType,
    pub safety: ScanSafety,
    pub resource: String,
    pub blocked: bool,
}

impl ScanEvent {
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{:?},{:?},{},{}",
            self.pid, self.syscall_name, self.access_type, self.safety, self.resource, self.blocked
        )
    }
}

pub struct ScanContext {
    home_dir: String,
    cwd: String,
    tmp: String,
    events: Vec<ScanEvent>,
    syscalls: HashSet<i64>,

    primed: bool,

    dirs_safe_to_read: Vec<Regex>,
    dirs_unsafe_to_read: Vec<Regex>,
}

impl ScanContext {
    pub fn new() -> ScanContext {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "".to_string());
        let cwd = std::env::current_dir()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|_| "".to_string());
        let tmp = std::env::temp_dir().to_string_lossy().to_string();

        let mut dirs_safe_to_read: Vec<Regex> = Vec::new();
        for dir in DIRS_SAFE_TO_READ.iter() {
            dirs_safe_to_read.push(Regex::new(dir).unwrap());
        }
        let mut dirs_unsafe_to_read: Vec<Regex> = Vec::new();
        for dir in DIRS_UNSAFE_TO_READ.iter() {
            dirs_unsafe_to_read.push(Regex::new(dir).unwrap());
        }

        let syscall_ids = VERIFY_SYSCALLS
            .iter()
            .map(|id| *id)
            .collect::<HashSet<i64>>();

        ScanContext {
            home_dir,
            cwd,
            tmp,
            events: vec![],
            syscalls: syscall_ids,
            primed: false,
            dirs_safe_to_read: dirs_safe_to_read,
            dirs_unsafe_to_read: dirs_unsafe_to_read,
        }
    }

    pub fn process_syscall(&mut self, syscall: &SyscallEvent) -> ScanEvent {
        let resource = syscall
            .extra_context
            .get(EXTRA_PATHNAME)
            .or_else(|| syscall.extra_context.get(EXTRA_ADDR))
            .map(|s| s.clone())
            .unwrap_or_else(|| "".to_string());
        let fd = syscall
            .arguments
            .iter()
            .find(|arg| match arg {
                SyscallArgument::Fd(_fd) => true,
                _ => false,
            })
            .map(|arg| match arg {
                SyscallArgument::Fd(fd) => *fd as i64,
                _ => -1,
            })
            .unwrap_or(-1);
        if !self.syscalls.contains(&(syscall.id as i64)) {
            return ScanEvent {
                pid: syscall.pid as u64,
                syscall_name: syscall.name.clone(),
                access_type: AccessType::Other,
                safety: ScanSafety::Safe,
                resource: resource,
                blocked: false,
            };
        }
        let access_type = classify_syscall_type(syscall);
        let safety = self.classify_safety(&access_type, &resource, fd);

        let id = syscall.id as i64;
        if id == SYS_OPEN || id == native::SYS_openat && !self.primed {
            if let Some(path) = syscall.extra_context.get(EXTRA_PATHNAME) {
                if path.ends_with(UNPICKLER) {
                    self.primed = true;
                    self.events.clear();
                }
            }
        }

        let event = ScanEvent {
            pid: syscall.pid as u64,
            syscall_name: syscall.name.clone(),
            access_type: access_type,
            safety: safety.clone(),
            resource: resource,
            blocked: match safety {
                ScanSafety::Unsafe => true,
                _ => false,
            },
        };
        if self.primed {
            self.events.push(event.clone());
        }
        event
    }

    fn classify_safety(&self, access_type: &AccessType, resource: &String, fd: i64) -> ScanSafety {
        match access_type {
            AccessType::FileSystemRead => {
                if fd >= 0 && fd < 3 {
                    ScanSafety::Safe
                } else if self
                    .dirs_safe_to_read
                    .iter()
                    .all(|dir_re| dir_re.is_match(&resource))
                {
                    ScanSafety::Safe
                } else if self
                    .dirs_unsafe_to_read
                    .iter()
                    .any(|dir_re| dir_re.is_match(&resource))
                {
                    ScanSafety::Unsafe
                } else {
                    ScanSafety::Suspicious
                }
            }
            AccessType::FileSystemWrite => {
                if fd >= 0 && fd < 3 {
                    ScanSafety::Safe
                } else if resource.starts_with(self.tmp.as_str()) {
                    ScanSafety::Safe
                } else {
                    ScanSafety::Unsafe
                }
            }
            AccessType::Network => {
                if fd >= 0 && fd < 3 {
                    ScanSafety::Safe
                } else {
                    ScanSafety::Unsafe
                }
            }
            AccessType::Process => ScanSafety::Unsafe,
            AccessType::Other => ScanSafety::Safe,
        }
    }
}

fn classify_syscall_type(syscall: &SyscallEvent) -> AccessType {
    let id = syscall.id as i64;
    if id == SYS_RMDIR {
        return AccessType::FileSystemWrite;
    }
    // if id == SYS_OPEN {
    //     return AccessType::FileSystemRead;
    // }
    match id {
        // native::SYS_openat => AccessType::FileSystemRead,
        // native::SYS_openat2 => AccessType::FileSystemRead,
        native::SYS_read => AccessType::FileSystemRead,
        native::SYS_write => AccessType::FileSystemWrite,
        native::SYS_unlinkat => AccessType::FileSystemWrite,
        native::SYS_renameat => AccessType::FileSystemWrite,
        native::SYS_renameat2 => AccessType::FileSystemWrite,
        native::SYS_connect | native::SYS_accept => AccessType::Network,
        native::SYS_execve | native::SYS_execveat => AccessType::Process,
        _ => AccessType::Other,
    }
}
