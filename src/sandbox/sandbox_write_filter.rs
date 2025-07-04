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

use crate::filters::flag_matcher::FlagMatcher;
use crate::filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher};
use crate::filters::utils::syscall_ids_by_names;
use std::collections::{HashMap, HashSet};

/// Creates a comprehensive write filter that blocks all filesystem-changing syscalls
/// and logs the attempts. This includes:
/// - Direct write operations (write, writev, pwrite, etc.)
/// - File creation (open/openat with O_CREAT flag)
/// - File and directory deletion (unlink, unlinkat, rmdir)
/// - File and directory renaming (rename, renameat)
/// - Directory creation (mkdir, mkdirat)
/// - Link creation (link, linkat, symlink, symlinkat)
/// - File truncation (truncate, ftruncate)
/// - Extended attributes modification (setxattr, fsetxattr, etc.)
/// - Other filesystem modification syscalls
pub(crate) fn create_write_filter() -> Vec<SyscallFilter> {
    // Comprehensive list of filesystem-changing syscalls
    let write_syscalls = vec![
        // Direct write operations
        "write",
        "writev",
        "pwrite",
        "pwrite64",
        "pwritev",
        "pwritev2",
        // File creation and modification
        "creat",
        "truncate",
        "ftruncate",
        // File and directory deletion
        "unlink",
        "unlinkat",
        "rmdir",
        // File and directory renaming/moving
        "rename",
        "renameat",
        "renameat2",
        // Directory creation
        "mkdir",
        "mkdirat",
        // Link creation
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        // Extended attributes
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "removexattrat",
        // File permissions and ownership
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "fchown",
        "lchown",
        "fchownat",
        // Time modification
        "utime",
        "utimes",
        "utimensat",
        "futimesat",
        // Other filesystem operations
        "mknod",
        "mknodat",
        "mount",
        "umount",
        "umount2",
        "pivot_root",
        "chroot",
    ];

    let open_syscalls = vec!["open", "openat", "openat2"];

    // Convert syscall names to IDs, filtering out any that don't exist on current architecture
    let write_syscall_ids: HashSet<i64> = syscall_ids_by_names(write_syscalls);
    let open_syscall_ids = syscall_ids_by_names(open_syscalls);

    // Create a flag matcher for O_CREAT to catch file creation attempts
    let flag_matcher = Some(FlagMatcher::new(vec!["O_CREAT".to_string()]));

    let filter_outcome = FilterOutcome {
        action: FilterAction::Block(-1), // EPERM error code
        tag: Some("WRITE_BLOCKED".to_string()),
        log: true,
    };
    vec![
        SyscallFilter {
            matcher: SyscallMatcher {
                syscall: open_syscall_ids.clone(),
                args: HashMap::new(),
                context_matcher: None,
                flag_matcher: flag_matcher,
            },
            outcome: filter_outcome.clone(),
        },
        SyscallFilter {
            matcher: SyscallMatcher {
                syscall: write_syscall_ids,
                args: HashMap::new(),
                context_matcher: None,
                flag_matcher: None,
            },
            outcome: filter_outcome.clone(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::utils::syscall_id_by_name;

    #[test]
    fn test_write_filter_blocks_write_syscalls() {
        let filters = create_write_filter();
        assert_eq!(filters.len(), 2); // Should have 2 filters: one for open with flags, one for write syscalls

        // Find the write syscalls filter (the one without flag_matcher)
        let write_filter = filters
            .iter()
            .find(|f| f.matcher.flag_matcher.is_none())
            .unwrap();

        // Test that write syscalls are included
        if let Some(write_id) = syscall_id_by_name("write") {
            assert!(write_filter.matcher.syscall.contains(&(write_id as i64)));
        }

        if let Some(unlink_id) = syscall_id_by_name("unlink") {
            assert!(write_filter.matcher.syscall.contains(&(unlink_id as i64)));
        }

        if let Some(mkdir_id) = syscall_id_by_name("mkdir") {
            assert!(write_filter.matcher.syscall.contains(&(mkdir_id as i64)));
        }
    }

    #[test]
    fn test_write_filter_outcome() {
        let filters = create_write_filter();

        // Test that both filters have the same outcome (block and log)
        for filter in &filters {
            match filter.outcome.action {
                FilterAction::Block(error_code) => assert_eq!(error_code, -1),
                _ => panic!("Expected Block action"),
            }

            assert!(filter.outcome.log);
            assert_eq!(filter.outcome.tag, Some("WRITE_BLOCKED".to_string()));
        }
    }

    #[test]
    fn test_write_filter_has_flag_matcher() {
        let filters = create_write_filter();

        // Find the open syscalls filter (the one with flag_matcher)
        let open_filter = filters
            .iter()
            .find(|f| f.matcher.flag_matcher.is_some())
            .unwrap();

        // Test that flag matcher is present for O_CREAT detection
        assert!(open_filter.matcher.flag_matcher.is_some());

        // Test that open syscalls are included in the flagged filter
        if let Some(open_id) = syscall_id_by_name("open") {
            assert!(open_filter.matcher.syscall.contains(&(open_id as i64)));
        }
        if let Some(openat_id) = syscall_id_by_name("openat") {
            assert!(open_filter.matcher.syscall.contains(&(openat_id as i64)));
        }
    }
}
