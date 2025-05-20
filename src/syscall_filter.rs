use std::collections::HashMap;

use nix::libc;
use regex::Regex;

use crate::syscall_event::SyscallEvent;

pub(crate) enum FilterAction {
    Process,
    Block { error: i32 },
    Ignore,
}

/// Represents a filter for syscall events.
/// Filters can match specific syscall numbers and their arguments.
/// Arguments can be specified by register index (0-5)
/// Some syscalls (such as reading/writing from file/socket) may have extra context (e.g. filepath or address)
/// that can be matched using regex.
/// Filter must specify the action to take when a syscall matches.
/// The default action is to block the syscall and return -ENOSYS.
pub(crate) struct SyscallFilter {
    syscall: i64,
    args: HashMap<u8, u64>,
    extras: HashMap<String, Regex>,
    action: FilterAction,
}

impl SyscallFilter {
    pub fn new(syscall: i64) -> Self {
        Self {
            syscall,
            args: HashMap::new(),
            extras: HashMap::new(),
            action: FilterAction::Block {
                error: -libc::ENOSYS,
            },
        }
    }

    pub fn matches(&self, syscall: &SyscallEvent) -> bool {
        if syscall.id as i64 != self.syscall {
            return false;
        }
        for (reg_idx, reg_value) in &self.args {
            if *reg_idx < 6 {
                if syscall.regs.regs[*reg_idx as usize] != *reg_value {
                    return false;
                }
            }
        }

        for (arg_name, regex) in &self.extras {
            if let Some(extra_value) = syscall.extra_context.get(arg_name.as_str()) {
                if !regex.is_match(extra_value) {
                    return false;
                }
            }
        }
        true
    }
}
