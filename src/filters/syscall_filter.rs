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

use std::collections::HashSet;

use nix::libc;

use crate::{
    filters::{
        argument_matcher::ArgumentMatcher, context_matcher::ContextMatcher, flag_matcher::FlagMatcher, matcher::StrMatcher
    },
    syscall_event::SyscallEvent,
    trace_process::TraceProcess,
};

const MAX_ARGS: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Default for FilterOutcome {
    fn default() -> Self {
        FilterOutcome {
            action: FilterAction::Block(-libc::ENOSYS),
            tag: None,
            log: true,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SyscallMatcher {
    pub syscall: HashSet<i64>,
    pub args: Vec<ArgumentMatcher>,
    pub context_matcher: Option<ContextMatcher>,
    pub flag_matcher: Option<FlagMatcher>,
}

impl SyscallMatcher {
    pub fn matches(&self, proc: &TraceProcess, syscall: &SyscallEvent) -> bool {
        let syscall_id = syscall.id as i64;
        if !self.syscall.is_empty() && !self.syscall.contains(&syscall_id) {
            return false;
        }

        for argument_matcher in &self.args {
            if argument_matcher.arg_index < MAX_ARGS {
                if !argument_matcher.matches(&syscall.regs.regs[argument_matcher.arg_index as usize]) {
                    return false;
                }
            }
        }

        if let Some(ContextMatcher::PathMatcher(ref path_matcher)) = self.context_matcher {
            if let Some(syscall_path) = syscall.get_extras_pathname() {
                if !path_matcher.matches(syscall_path) {
                    return false;
                } else if path_matcher.only_created_by_process
                    && proc.is_created_by_process(syscall_path)
                {
                    return false;
                }
            } else {
                // if there is a filter expecting filepath and event doesn't have filepath, don't match
                return false;
            }
        }

        if let Some(ContextMatcher::AddressMatcher(ref address_matcher)) = self.context_matcher {
            if let Some(syscall_addr) = syscall.get_extras_addr() {
                if !address_matcher.matches(syscall_addr) {
                    return false;
                }
            } else {
                // if there is a filter expecting addr and event doesn't have addr, don't match
                return false;
            }
        }

        if let Some(ref flag_matcher) = self.flag_matcher {
            if let Some(flags) = syscall.get_extras_flags() {
                if !flag_matcher.matches(flags) {
                    return false;
                }
            } else {
                // if there is a filter expecting flags and event doesn't have flags, don't match
                return false;
            }
        }

        true
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
    pub matcher: SyscallMatcher,
    pub outcome: FilterOutcome,
}
