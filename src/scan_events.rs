use std::collections::HashSet;

use regex::Regex;
use serde::Serialize;
use syscall_numbers::{native, x86_64};

use crate::{
    scan_config::Config,
    syscall_args::SyscallArgument,
    syscall_common::{EXTRA_ADDR, EXTRA_PATHNAME},
    syscall_event::SyscallEvent,
};

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
    events: Vec<ScanEvent>,
    syscalls: HashSet<i64>,

    primed: bool,

    dirs_safe_to_read: Vec<Regex>,
    dirs_safe_to_write: Vec<Regex>,
}

impl ScanContext {
    pub fn new_from_config(cfg: Config) -> ScanContext {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "".to_string());

        let mut dirs_safe_to_read = HashSet::<String>::new();
        for dir in cfg.allow_reads_from.iter() {
            dirs_safe_to_read.insert(dir.clone());
        }
        let mut dirs_safe_to_write = HashSet::<String>::new();
        for dir in cfg.allow_writes_to.iter() {
            dirs_safe_to_read.insert(dir.clone());
            dirs_safe_to_write.insert(dir.clone());
        }

        ScanContext {
            home_dir,
            events: vec![],
            syscalls: HashSet::new(),
            primed: false,
            dirs_safe_to_read: dirs_safe_to_read
                .iter()
                .map(|dir| Regex::new(dir).unwrap())
                .collect(),
            dirs_safe_to_write: dirs_safe_to_write
                .iter()
                .map(|dir| Regex::new(dir).unwrap())
                .collect(),
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
        // TODO: check if we need to prime the context before starting sandbox
        // if id == SYS_OPEN || id == native::SYS_openat && !self.primed {
        //     if let Some(path) = syscall.extra_context.get(EXTRA_PATHNAME) {
        //         if path.ends_with(UNPICKLER) {
        //             self.primed = true;
        //             self.events.clear();
        //         }
        //     }
        // }

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
                    .dirs_safe_to_write
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
                } else if self.is_safe(resource.clone()) {
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

    fn is_safe(&self, _resource: String) -> bool {
        todo!()
    }
}

fn classify_syscall_type(syscall: &SyscallEvent) -> AccessType {
    let id = syscall.id as i64;
    #[cfg(target_arch = "x86_64")]
    match id {
        native::SYS_openat | native::SYS_openat2 | native::SYS_read => AccessType::FileSystemRead,
        native::SYS_write | native::SYS_unlinkat | native::SYS_renameat | native::SYS_renameat2 => {
            AccessType::FileSystemWrite
        }
        native::SYS_connect | native::SYS_accept => AccessType::Network,
        native::SYS_execve | native::SYS_execveat => AccessType::Process,
        _ => AccessType::Other,
    }
    #[cfg(target_arch = "aarch64")]
    match id {
        native::SYS_openat2 => AccessType::FileSystemRead,
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
