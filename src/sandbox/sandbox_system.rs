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

use crate::filters::{syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher}, utils::syscall_ids_by_names};

pub(crate) fn create_system_filter() -> SyscallFilter {
    let read_syscalls = vec![
        "reboot",
    ];
    let read_syscall_ids: HashSet<i64> = syscall_ids_by_names(read_syscalls);

    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: read_syscall_ids,
            args: HashMap::default(),
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            tag: Some("reboot".to_string()),
            log: true,
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_system_filter_allows_reboot() {
        let filter = create_system_filter();
        // The filter should allow the "reboot" syscall
        assert_eq!(filter.outcome.action, FilterAction::Allow);
        assert_eq!(filter.outcome.tag.as_deref(), Some("reboot"));
        assert!(filter.outcome.log);

        // The matcher should contain the syscall id for "reboot"
        let reboot_syscall_ids = syscall_ids_by_names(vec!["reboot"]);
        assert_eq!(filter.matcher.syscall, reboot_syscall_ids);
    }

    #[test]
    fn test_create_system_filter_no_args_or_context() {
        let filter = create_system_filter();
        // The matcher should not match on args, context, or flags
        assert!(filter.matcher.args.is_empty());
        assert!(filter.matcher.context_matcher.is_none());
        assert!(filter.matcher.flag_matcher.is_none());
    }

    #[test]
    fn test_create_system_filter_does_not_allow_other_syscalls() {
        let filter = create_system_filter();
        // The filter should not match unrelated syscalls
        let unrelated_syscall_ids = syscall_ids_by_names(vec!["open", "close", "read"]);
        for id in unrelated_syscall_ids {
            assert!(!filter.matcher.syscall.contains(&id));
        }
    }
}

