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

use std::collections::{HashMap, HashSet};

use crate::filters::path_matcher::PathMatcher;
use crate::filters::{context_matcher::ContextMatcher, matcher::StrMatchOp, syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher}, utils::syscall_ids_by_names};

pub(crate) fn create_process_filter(allowed_binaries: Vec<&str>) -> SyscallFilter {
    let read_syscalls = vec![
        "execve", "execveat"
    ];
    let exec_syscall_ids: HashSet<i64> = syscall_ids_by_names(read_syscalls);

    let path_matcher = if !allowed_binaries.is_empty() {
        Some(ContextMatcher::PathMatcher(PathMatcher::new(
                allowed_binaries.into_iter().map(|s| s.to_string()).collect(),
                StrMatchOp::Suffix,
                false,
            )))
    } else {
        None
    };

    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: exec_syscall_ids,
            args: HashMap::default(),
            context_matcher: path_matcher,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(-1),
            tag: Some("reboot".to_string()),
            log: true,
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_process_filter_with_binaries() {
        let allowed = vec!["/usr/bin/bash", "/bin/sh"];
        let filter = create_process_filter(allowed.clone());

        // Check that the filter matches execve/execveat syscalls
        let execve_id = *syscall_ids_by_names(vec!["execve"]).iter().next().unwrap();
        assert!(filter.matcher.syscall.contains(&execve_id));

        // Check that the context matcher is set
        assert!(filter.matcher.context_matcher.is_some());

        // Check that the filter action is Block(-1)
        match filter.outcome.action {
            FilterAction::Block(code) => assert_eq!(code, -1),
            _ => panic!("Expected Block action"),
        }

        // Check that the tag is "reboot"
        assert_eq!(filter.outcome.tag.as_deref(), Some("reboot"));
        assert!(filter.outcome.log);
    }

    #[test]
    fn test_create_process_filter_empty_binaries() {
        let filter = create_process_filter(vec![]);

        // Context matcher should be None
        assert!(filter.matcher.context_matcher.is_none());

        // Should still block execve/execveat
        let execve_id = *syscall_ids_by_names(vec!["execve"]).iter().next().unwrap();
        assert!(filter.matcher.syscall.contains(&execve_id));
    }
}
