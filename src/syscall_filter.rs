use std::{collections::HashMap, path};

use nix::libc;
use regex::Regex;

use crate::{
    syscall_common::{EXTRA_ADDR, EXTRA_PATHNAME},
    syscall_event::SyscallEvent,
    trace_process::TraceProcess,
};

const MAX_ARGS: u8 = 6;
pub(crate) enum FilterAction {
    Block(i32),
    Allow,
}

pub(crate) struct FilterOutcome {
    pub action: FilterAction,
    pub tag: Option<String>,
    pub log: bool,
}

pub(crate) struct ExtraMatcher {
    pub match_created_by_process: bool,
    pub extras: HashMap<String, Regex>,
}

/// Represents a filter for syscall events.
/// Filters can match specific syscall numbers and their arguments.
/// Arguments can be specified by register index (0-5)
/// Some syscalls (such as reading/writing from file/socket) may have extra context (e.g. filepath or address)
/// that can be matched using regex.
/// Filter must specify the action to take when a syscall matches.
/// The default action is to block the syscall and return -ENOSYS.
pub(crate) struct SyscallFilter {
    pub syscall: i64,
    pub args: HashMap<u8, u64>,
    pub match_path_created_by_process: bool,
    pub path: Option<Regex>,
    pub addr: Option<Regex>,
    pub outcome: FilterOutcome,
}

impl SyscallFilter {
    pub fn new(syscall: i64) -> Self {
        Self {
            syscall,
            args: HashMap::new(),
            path: None,
            addr: None,
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Block(libc::ENOSYS),
                tag: None,
                log: false,
            },
        }
    }

    pub fn matches(&self, proc: &TraceProcess, syscall: &SyscallEvent) -> bool {
        if syscall.id as i64 != self.syscall {
            return false;
        }
        for (reg_idx, reg_value) in &self.args {
            if *reg_idx < MAX_ARGS {
                if syscall.regs.regs[*reg_idx as usize] != *reg_value {
                    return false;
                }
            }
        }

        if let Some(path) = &self.path {
            if let Some(syscall_abs_path) = syscall.get_abs_filepath() {
                if !path.is_match(&syscall_abs_path) {
                    // path doesn't match
                    return false;
                } else {
                    // if we only interested in the paths that were created by this process
                    // and this path was not created by this process, then we don't want to match
                    if self.match_path_created_by_process
                        && !proc.is_created_by_process(&syscall_abs_path)
                    {
                        return false;
                    }
                }
            }
        }

        if let Some(addr) = &self.addr {
            if let Some(syscall_addr) = syscall.extra_context.get(EXTRA_ADDR) {
                if !addr.is_match(&syscall_addr) {
                    // addr doesn't match
                    return false;
                }
            }
        }

        true
    }
}
