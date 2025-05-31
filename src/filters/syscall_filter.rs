use std::collections::{HashMap, HashSet};

use nix::libc;

use crate::{
    filters::{
        flag_matcher::FlagMatcher,
        matcher::StrMatcher,
        path_matcher::{
            PathMatchOp::{self, Prefix},
            PathMatcher,
        },
    },
    syscall_common::{EXTRA_FLAGS, EXTRA_PATHNAME},
    syscall_event::SyscallEvent,
    trace_process::TraceProcess,
};

const MAX_ARGS: u8 = 6;

#[derive(Debug, Clone)]
pub(crate) enum FilterAction {
    Block(i32),
    Allow,
}

/// Filter outcome represents the action to take when a syscall matches a filter.
/// It can either block the syscall (returning a specific error code)
/// or allow it to proceed.
/// The `tag` can be used to label the syscall for logging or further processing.
/// The `log` field indicates whether the syscall should be logged when it matches the filter.
#[derive(Debug, Clone)]
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

/// Represents a filter for syscall events.
/// Filters can match specific syscall numbers and their arguments.
/// Arguments can be specified by register index (0-5)
/// Some syscalls (such as reading/writing from file/socket) may have extra context (e.g. filepath or address)
/// that can be matched using regex.
/// Filter must specify the action to take when a syscall matches.
/// The default action is to block the syscall and return -ENOSYS.
#[derive(Debug, Clone)]
pub(crate) struct SyscallFilter {
    pub syscall: HashSet<i64>,
    pub args: HashMap<u8, HashSet<u64>>,
    pub match_path_created_by_process: bool,
    pub path_matcher: Option<PathMatcher>,
    pub flag_matcher: Option<FlagMatcher>,
    pub outcome: FilterOutcome,
}

impl SyscallFilter {
    pub fn stdio_allow(syscall: i64) -> Self {
        let mut args = HashMap::new();
        let mut arg_set = HashSet::new();
        arg_set.insert(0);
        arg_set.insert(1);
        arg_set.insert(2);
        args.insert(0, arg_set);
        Self {
            syscall: [syscall].into(),
            args: args.clone(),
            path_matcher: None,
            flag_matcher: None,
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                tag: None,
                log: true,
            },
        }
    }

    pub fn allow(syscall: &[i64], path: &Vec<String>) -> Self {
        Self {
            syscall: syscall.iter().cloned().collect(),
            args: HashMap::new(),
            path_matcher: Some(PathMatcher::new(path.clone(), Prefix)),
            flag_matcher: None,
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                tag: None,
                log: true,
            },
        }
    }

    pub fn with_paths(
        syscall: i64,
        allow: bool,
        paths: &[&str],
        path_match_op: PathMatchOp,
    ) -> Self {
        let path_list = paths.iter().map(|&s| s.to_string()).collect();
        Self {
            syscall: [syscall].into(),
            args: HashMap::new(),
            path_matcher: Some(PathMatcher::new(path_list, path_match_op)),
            flag_matcher: None,
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: if allow {
                    FilterAction::Allow
                } else {
                    FilterAction::Block(libc::ENOSYS)
                },
                tag: None,
                log: true,
            },
        }
    }

    pub fn with_flags(syscall: i64, allow: bool, flags: &[&str]) -> Self {
        let flag_list = flags.iter().map(|&s| s.to_string()).collect();
        Self {
            syscall: [syscall].into(),
            args: HashMap::new(),
            path_matcher: None,
            flag_matcher: Some(FlagMatcher::new(flag_list)),
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: if allow {
                    FilterAction::Allow
                } else {
                    FilterAction::Block(libc::ENOSYS)
                },
                tag: None,
                log: true,
            },
        }
    }

    pub fn with_paths_and_flags(
        syscall: i64,
        allow: bool,
        paths: &Vec<String>,
        path_match_op: PathMatchOp,
        flags: &Vec<String>,
    ) -> Self {
        Self {
            syscall: [syscall].into(),
            args: HashMap::new(),
            path_matcher: Some(PathMatcher::new(paths.clone(), path_match_op)),
            flag_matcher: Some(FlagMatcher::new(flags.clone())),
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: if allow {
                    FilterAction::Allow
                } else {
                    FilterAction::Block(libc::ENOSYS)
                },
                tag: None,
                log: true,
            },
        }
    }

    pub fn block(syscall: &[i64]) -> Self {
        Self {
            syscall: syscall.iter().cloned().collect(),
            args: HashMap::new(),
            path_matcher: None,
            flag_matcher: None,
            match_path_created_by_process: false,
            outcome: FilterOutcome {
                action: FilterAction::Block(libc::ENOSYS),
                tag: None,
                log: true,
            },
        }
    }

    pub fn matches(&self, proc: &TraceProcess, syscall: &SyscallEvent) -> bool {
        let syscall_id = syscall.id as i64;
        if !self.syscall.is_empty() && !self.syscall.contains(&syscall_id) {
            return false;
        }
        for (reg_idx, reg_value) in &self.args {
            if *reg_idx < MAX_ARGS {
                if !reg_value.contains(&syscall.regs.regs[*reg_idx as usize]) {
                    return false;
                }
            }
        }

        if let Some(ref path_matcher) = self.path_matcher {
            if let Some(syscall_path) = syscall.extra_context.get(EXTRA_PATHNAME) {
                if !path_matcher.matches(syscall_path) {
                    return false;
                } else if self.match_path_created_by_process
                    && proc.is_created_by_process(syscall_path)
                {
                    return false;
                }
            }
        }
        if let Some(ref flag_matcher) = self.flag_matcher {
            if let Some(flags) = syscall.extra_context.get(EXTRA_FLAGS) {
                if !flag_matcher.matches(flags) {
                    return false;
                }
            }
        }

        true
    }
}
