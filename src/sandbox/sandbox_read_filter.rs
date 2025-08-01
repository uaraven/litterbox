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

use crate::filters::{
    syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher},
    utils::syscall_ids_by_names,
};

pub(crate) fn create_reader_filter() -> SyscallFilter {
    let read_syscalls = vec![
        // read operations
        "read",
        "pread",
        "readv",
        // opening files
        "open",
        "openat",
        // file descriptor operations
        "stat",
        "fstat",
        "fstatat",
        "lstat",
        "getdents",
        "getdents64",
    ];
    let read_syscall_ids: HashSet<i64> = syscall_ids_by_names(read_syscalls);

    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: read_syscall_ids,
            args: vec![],
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            tag: Some("read".to_string()),
            log: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::utils::syscall_id_by_name;

    #[test]
    fn test_reader_filter_includes_read_syscalls() {
        let filter = create_reader_filter();

        // Test that all expected read syscalls are included
        let expected_syscalls = vec!["read", "pread", "readv", "open", "openat"];

        for syscall_name in expected_syscalls {
            if let Some(syscall_id) = syscall_id_by_name(syscall_name) {
                assert!(
                    filter.matcher.syscall.contains(&(syscall_id as i64)),
                    "Filter should include syscall: {}",
                    syscall_name
                );
            }
        }
    }

    #[test]
    fn test_reader_filter_outcome_allows_and_logs() {
        let filter = create_reader_filter();

        // Test that the filter allows syscalls and logs them
        match filter.outcome.action {
            FilterAction::Allow => {} // Expected
            _ => panic!("Reader filter should allow syscalls"),
        }

        assert!(filter.outcome.log, "Reader filter should log syscalls");
        assert_eq!(
            filter.outcome.tag, Some("read".to_string()),
            "Reader filter should tag syscalls with 'read'"
        );
    }

    #[test]
    fn test_reader_filter_has_no_context_matcher() {
        let filter = create_reader_filter();

        // Test that the filter has no context matcher (no path/address filtering)
        assert!(filter.matcher.context_matcher.is_none());
    }

    #[test]
    fn test_reader_filter_has_no_flag_matcher() {
        let filter = create_reader_filter();

        // Test that the filter has no flag matcher
        assert!(filter.matcher.flag_matcher.is_none());
    }

    #[test]
    fn test_reader_filter_has_no_args_matcher() {
        let filter = create_reader_filter();

        // Test that the filter has no arguments matcher
        assert!(filter.matcher.args.is_empty());
    }

    #[test]
    fn test_reader_filter_syscall_count() {
        let filter = create_reader_filter();

        // Test that the filter has the expected number of syscalls
        // Should include all read-related syscalls defined in create_reader_filter()
        let expected_syscalls = vec![
            "read", "pread", "readv", "open", "openat",
            "stat", "fstat", "fstatat", "lstat", "getdents", "getdents64"
        ];
        let expected_count = expected_syscalls
            .iter()
            .filter(|&&name| syscall_id_by_name(name).is_some())
            .count();

        assert_eq!(
            filter.matcher.syscall.len(),
            expected_count,
            "Filter should have {} syscalls for current architecture",
            expected_count
        );
    }
}
