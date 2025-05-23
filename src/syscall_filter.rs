use std::{
    collections::{HashMap, HashSet},
    path,
};

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

impl FilterOutcome {
    pub fn default() -> Self {
        FilterOutcome {
            action: FilterAction::Block(-libc::ENOSYS),
            tag: None,
            log: true,
        }
    }
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
    pub args: HashMap<u8, HashSet<u64>>,
    pub match_path_created_by_process: bool,
    pub extras: HashMap<String, Regex>,
    pub outcome: FilterOutcome,
}

impl SyscallFilter {
    pub fn new_stdio_allow(syscall: i64) -> Self {
        let mut args = HashMap::new();
        let mut arg_set = HashSet::new();
        arg_set.insert(0);
        arg_set.insert(1);
        arg_set.insert(2);
        args.insert(0, arg_set);
        Self {
            syscall,
            args,
            extras: HashMap::new(),
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                tag: None,
                log: true,
            },
        }
    }

    pub fn block(syscall: i64) -> Self {
        Self {
            syscall,
            args: HashMap::new(),
            extras: HashMap::new(),
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Block(libc::ENOSYS),
                tag: None,
                log: true,
            },
        }
    }

    pub fn matches(&self, proc: &TraceProcess, syscall: &SyscallEvent) -> bool {
        if self.syscall != -1 && syscall.id as i64 != self.syscall {
            return false;
        }
        for (reg_idx, reg_value) in &self.args {
            if *reg_idx < MAX_ARGS {
                if !reg_value.contains(&syscall.regs.regs[*reg_idx as usize]) {
                    return false;
                }
            }
        }

        for (key, regex) in &self.extras {
            if let Some(value) = syscall.extra_context.get(key.as_str()) {
                if !regex.is_match(value) {
                    return false;
                } else if *key == EXTRA_PATHNAME.to_string()
                    && self.match_path_created_by_process
                    && !proc.is_created_by_process(value)
                {
                    return false;
                }
            } else {
                // if the key is not present in the syscall's extras, we don't match
                return false;
            }
        }

        true
    }
}
