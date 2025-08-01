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
use crate::filters::argument_matcher::{ArgValue, ArgumentMatcher};
use crate::filters::context_matcher::ContextMatcher;
use crate::filters::flag_matcher::FlagMatcher;
use crate::filters::str_matcher::StrMatchOp;
use crate::filters::path_matcher::PathMatcher;
use crate::filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher};
use crate::filters::utils::syscall_ids_by_names;
use std::collections::HashSet;

/// Creates the filter for open/openat/openat2 syscalls
/// These filters are only triggered by O_CREAT and O_TRUNC flags. Creating a file or
/// opening it with truncation are considered write operations
fn create_filter_for_open_syscall(
    ctx_matcher: Option<ContextMatcher>,
    outcome: &FilterOutcome,
) -> SyscallFilter {
    let open_syscalls = vec!["open", "openat", "openat2"];
    let open_syscall_ids: HashSet<i64> = syscall_ids_by_names(open_syscalls);

    // Create a flag matcher for O_CREAT to catch file creation attempts and O_TRUNC to catch truncation attempts
    let flag_matcher = Some(FlagMatcher::new(vec![
        "O_CREAT".to_string(),
        "O_TRUNC".to_string(),
    ]));

    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: open_syscall_ids,
            args: vec![],
            context_matcher: ctx_matcher,
            flag_matcher,
        },
        outcome: outcome.clone(),
    }
}

/// Creates filters for mknod/mknodat syscalls
/// These filters only trigger on syscalls with S_IFSREG flag set, i.e. when creating a normal
/// file.
fn create_filter_for_mknod(
    ctx_matcher: Option<ContextMatcher>,
    outcome: &FilterOutcome,
) -> Vec<SyscallFilter> {
    const S_IFSREG: u64 = 0o100000; // Regular file

    let mknod_arg_matcher = ArgumentMatcher::new(1, vec![ArgValue::BitSet(S_IFSREG)]);
    let mknodat_arg_matcher = ArgumentMatcher::new(2, vec![ArgValue::BitSet(S_IFSREG)]);

    vec![
        SyscallFilter {
            matcher: SyscallMatcher {
                syscall: syscall_ids_by_names(vec!["mknod"]),
                args: vec![mknod_arg_matcher],
                context_matcher: ctx_matcher.clone(),
                flag_matcher: None,
            },
            outcome: outcome.clone(),
        },
        SyscallFilter {
            matcher: SyscallMatcher {
                syscall: syscall_ids_by_names(vec!["mknodat"]),
                args: vec![mknodat_arg_matcher],
                context_matcher: ctx_matcher,
                flag_matcher: None,
            },
            outcome: outcome.clone(),
        },
    ]
}

/// Creates generic filter for all write operations.
fn create_filter_for_writes(
    ctx_matcher: Option<ContextMatcher>,
    outcome: &FilterOutcome,
) -> SyscallFilter {
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
        // File creation
        "mknod",
        "mknodat",
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
        // Other filesystem operations
        "mount",
        "umount",
        "umount2",
        "pivot_root",
        "chroot",
    ];

    // Convert syscall names to IDs, filtering out any that don't exist on current architecture
    let write_syscall_ids: HashSet<i64> = syscall_ids_by_names(write_syscalls);
    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: write_syscall_ids,
            args: vec![],
            context_matcher: ctx_matcher,
            flag_matcher: None,
        },
        outcome: outcome.clone(),
    }
}

/// Creates a comprehensive write filter that blocks all filesystem-changing syscalls
/// and logs the attempts. This includes:
/// - Direct write operations (write, writev, pwrite, etc.)
/// - File creation (open/openat with O_CREAT or O_TRUNC flag)
/// - File and directory deletion (unlink, unlinkat, rmdir)
/// - File and directory renaming (rename, renameat)
/// - Directory creation (mkdir, mkdirat)
/// - Link creation (link, linkat, symlink, symlinkat)
/// - File truncation (truncate, ftruncate)
/// - Extended attributes modification (setxattr, fsetxattr, etc.)
/// - Other filesystem modification syscalls
///
/// All operations where the file path starts with any of the prefixes in `allowed_paths`
/// argument are allowed to continue, but logged
pub(crate) fn create_write_filter(allowed_paths: Vec<&str>) -> Vec<SyscallFilter> {
    let filter_outcome_block = FilterOutcome {
        action: FilterAction::Block(-1), // EPERM error code
        tag: Some("write".to_string()),
        log: true,
    };
    let filter_outcome_allow = FilterOutcome {
        action: FilterAction::Allow,
        tag: Some("write".to_string()),
        log: true,
    };

    let mut filters = vec![];
    filters.push(create_stdout_stderr_write_filter());
    if !allowed_paths.is_empty() {
        let ctx_matcher = Some(ContextMatcher::PathMatcher(PathMatcher::new(
            allowed_paths.into_iter().map(|s| s.to_string()).collect(),
            StrMatchOp::Prefix,
            false,
        )));
        filters.push(create_filter_for_open_syscall(
            ctx_matcher.clone(),
            &filter_outcome_allow,
        ));
        filters.extend(create_filter_for_mknod(
            ctx_matcher.clone(),
            &filter_outcome_allow,
        ));
        filters.push(create_filter_for_writes(
            ctx_matcher.clone(),
            &filter_outcome_allow,
        ));
    }
    filters.push(create_filter_for_open_syscall(None, &filter_outcome_block));
    filters.extend(create_filter_for_mknod(None, &filter_outcome_block));
    filters.push(create_filter_for_writes(None, &filter_outcome_block));

    filters
}

/// Creates a SyscallFilter that allows write operations to stdout (fd 1) and stderr (fd 2).
/// This filter allows write syscalls when the file descriptor is 1 or 2.
pub(crate) fn create_stdout_stderr_write_filter() -> SyscallFilter {
    let write_syscalls = vec![
        "write",
        "writev",
        "pwrite",
        "pwrite64",
        "pwritev",
        "pwritev2",
    ];

    let write_syscall_ids: HashSet<i64> = syscall_ids_by_names(write_syscalls);

    // Create argument matcher for file descriptor (first argument, index 0)
    // Match fd 1 (stdout) and fd 2 (stderr)
    let fd_matcher = ArgumentMatcher::new(0, vec![ArgValue::Equal(1), ArgValue::Equal(2)]);

    let filter_outcome = FilterOutcome {
        action: FilterAction::Allow,
        tag: Some("write".to_string()),
        log: true,
    };

    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: write_syscall_ids,
            args: vec![fd_matcher],
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: filter_outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter_listener::FilteringLogger;
    use crate::filters::utils::syscall_id_by_name;
    use crate::regs::Regs;
    use crate::syscall_common::{EXTRA_FLAGS, EXTRA_PATHNAME};
    use crate::syscall_event::{ExtraData, SyscallStopType};
    use crate::syscall_event::{SyscallEvent, SyscallEventListener};
    use crate::trace_process::TraceProcess;
    use std::collections::HashMap;

    #[test]
    fn test_write_filter_outcome() {
        let filters = create_write_filter(vec![]);

        // Test that all but first filter have the same outcome (block and log)
        // first one should allow writes to stdout and stderr
        for filter in filters.iter().skip(1) {
            match filter.outcome.action {
                FilterAction::Block(error_code) => assert_eq!(error_code, -1),
                _ => panic!("Expected Block action"),
            }

            assert!(filter.outcome.log);
            assert_eq!(filter.outcome.tag, Some("write".to_string()));
        }
    }

    #[test]
    fn test_write_filter_has_flag_matcher() {
        let filters = create_write_filter(vec![]);

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

    #[test]
    fn test_open_with_o_trunc_flag_blocked() {
        let filters = create_write_filter(vec![]);
        let open_filter = filters
            .iter()
            .find(|f| f.matcher.flag_matcher.is_some())
            .unwrap();

        // Create a mock TraceProcess
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Create a mock SyscallEvent for open syscall with O_TRUNC flag
        let mut extra = HashMap::new();
        extra.insert(EXTRA_FLAGS, "O_TRUNC".to_string());

        let mut regs = Regs::default();
        if let Some(open_id) = syscall_id_by_name("openat") {
            regs.syscall_id = open_id;
        }

        let event = SyscallEvent {
            id: regs.syscall_id,
            name: "open".to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: extra,
            blocked: false,
            label: None,
        };

        // Test that the filter matches the event
        assert!(open_filter.matcher.matches(&proc, &event));

        // Verify that the action is Block with error code -1
        match open_filter.outcome.action {
            FilterAction::Block(error_code) => assert_eq!(error_code, -1),
            _ => panic!("Expected Block action for open with O_TRUNC"),
        }
    }

    #[test]
    fn test_openat_with_o_trunc_flag_blocked() {
        let filters = create_write_filter(vec![]);
        let open_filter = filters
            .iter()
            .find(|f| f.matcher.flag_matcher.is_some())
            .unwrap();

        // Create a mock TraceProcess
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Create a mock SyscallEvent for openat syscall with O_TRUNC flag
        let mut extra = HashMap::new();
        extra.insert(EXTRA_FLAGS, "O_TRUNC".to_string());

        let mut regs = Regs::default();
        if let Some(openat_id) = syscall_id_by_name("openat") {
            regs.syscall_id = openat_id;
        }

        let event = SyscallEvent {
            id: regs.syscall_id,
            name: "openat".to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: extra,
            blocked: false,
            label: None,
        };

        // Test that the filter matches the event
        assert!(open_filter.matcher.matches(&proc, &event));

        // Verify that the action is Block with error code -1
        match open_filter.outcome.action {
            FilterAction::Block(error_code) => assert_eq!(error_code, -1),
            _ => panic!("Expected Block action for openat with O_TRUNC"),
        }
    }

    fn create_test_syscall_event(
        syscall_name: &str,
        extra: &ExtraData,
        regs: &Regs,
    ) -> SyscallEvent {
        SyscallEvent {
            id: regs.syscall_id,
            name: syscall_name.to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: extra.clone(),
            blocked: false,
            label: None,
        }
    }

    fn test_event_filter(
        filters: Vec<SyscallFilter>,
        proc: &TraceProcess,
        event: &SyscallEvent,
        expected_blocked: bool,
    ) {
        let mut filtering_logger = FilteringLogger::new(filters, None, None);
        let result = filtering_logger.process_event(&proc, &event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().blocked, expected_blocked);
    }

    #[test]
    fn test_create_write_filter_with_tmp_path_blocked() {
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
        let filters = create_write_filter(vec!["/tmp"]);

        // Test write syscall to a path outside /tmp should be blocked
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/home/user/file.txt".to_string());

        let mut regs = Regs::default();
        if let Some(write_id) = syscall_id_by_name("write") {
            regs.syscall_id = write_id;
        }

        let event = create_test_syscall_event("write", &extra, &regs);

        test_event_filter(filters, &proc, &event, true);
    }

    #[test]
    fn test_create_write_filter_with_tmp_path_allowed() {
        let filters = create_write_filter(vec!["/tmp"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test write syscall to a path inside /tmp should be allowed
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/tmp/test_file.txt".to_string());

        let mut regs = Regs::default();
        if let Some(write_id) = syscall_id_by_name("write") {
            regs.syscall_id = write_id;
        }

        let event = create_test_syscall_event("write", &extra, &regs);

        test_event_filter(filters, &proc, &event, false);
    }

    #[test]
    fn test_create_write_filter_with_tmp_path_mkdir_blocked() {
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
        let filters = create_write_filter(vec!["/tmp"]);

        // Test mkdir syscall to a path outside /tmp should be blocked
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/home/user/newdir".to_string());

        let mut regs = Regs::default();
        if let Some(mkdir_id) = syscall_id_by_name("mkdirat") {
            regs.syscall_id = mkdir_id;
        }

        let event = create_test_syscall_event("mkdirat", &extra, &regs);

        test_event_filter(filters, &proc, &event, true);
    }

    #[test]
    fn test_create_write_filter_with_tmp_path_mkdir_allowed() {
        let filters = create_write_filter(vec!["/tmp"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test mkdir syscall to a path inside /tmp should be allowed
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/tmp/newdir".to_string());

        let mut regs = Regs::default();
        if let Some(mkdir_id) = syscall_id_by_name("mkdir") {
            regs.syscall_id = mkdir_id;
        }

        let event = create_test_syscall_event("mkdir", &extra, &regs);

        test_event_filter(filters, &proc, &event, false);
    }

    #[test]
    fn test_write_filter_allows_stdout() {
        let filter = create_stdout_stderr_write_filter();
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test write to stdout (fd 1)
        let mut regs = Regs::default();
        if let Some(write_id) = syscall_id_by_name("write") {
            regs.syscall_id = write_id;
            regs.regs[0] = 1; // stdout fd
        }

        let event = SyscallEvent {
            id: regs.syscall_id,
            name: "write".to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: HashMap::new(),
            blocked: false,
            label: None,
        };

        // Verify that the filter matches stdout writes
        assert!(filter.matcher.matches(&proc, &event));

        // Verify that the action is Allow with correct tag
        match filter.outcome.action {
            FilterAction::Allow => {},
            _ => panic!("Expected Allow action for stdout writes"),
        }
        assert!(filter.outcome.log);
        assert_eq!(filter.outcome.tag, Some("write".to_string()));
    }

    #[test]
    fn test_write_filter_allows_stderr() {
        let filter = create_stdout_stderr_write_filter();
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test write to stderr (fd 2)
        let mut regs = Regs::default();
        if let Some(write_id) = syscall_id_by_name("write") {
            regs.syscall_id = write_id;
            regs.regs[0] = 2; // stderr fd
        }

        let event = SyscallEvent {
            id: regs.syscall_id,
            name: "write".to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: HashMap::new(),
            blocked: false,
            label: None,
        };

        // Verify that the filter matches stderr writes
        assert!(filter.matcher.matches(&proc, &event));

        // Verify that the action is Allow with correct tag
        match filter.outcome.action {
            FilterAction::Allow => {},
            _ => panic!("Expected Allow action for stderr writes"),
        }
        assert!(filter.outcome.log);
        assert_eq!(filter.outcome.tag, Some("write".to_string()));
    }
}
