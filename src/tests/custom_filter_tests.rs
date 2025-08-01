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
#[cfg(test)]
use nix::libc;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use syscall_numbers::native;

use crate::filters::syscall_filter::SyscallMatcher;
#[cfg(test)]
use crate::{
    filters::{
        context_matcher::ContextMatcher,
        str_matcher::StrMatchOp,
        path_matcher::PathMatcher,
        syscall_filter::{FilterOutcome, SyscallFilter},
    },
    regs::Regs,
    syscall_common::EXTRA_PATHNAME,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
    FilteringLogger,
};

#[test]
fn test_block_open_in_forbidden_folder() {
    let block_open = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_write as i64].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                vec!["/forbidden_folder".to_string()],
                StrMatchOp::Prefix,
                false,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::new(vec![block_open], None, None);
    let mut proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
    proc.add_created_path("/forbidden_folder/file.txt".to_string());
    proc.add_fd(
        5,
        EXTRA_PATHNAME,
        String::from("/forbidden_folder/file.txt"),
        0,
    );
    let mut regs = Regs::default();
    regs.syscall_id = native::SYS_write as u64;
    regs.regs[0] = 5; // some file descriptor, not stdin, stdout, or stderr

    let mut extra = HashMap::new();
    extra.insert(EXTRA_PATHNAME, "/forbidden_folder/file.txt".to_string());

    let event = SyscallEvent {
        id: regs.syscall_id,
        name: "write".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: regs.clone(),
        return_value: 0,
        stop_type: crate::syscall_event::SyscallStopType::Enter,
        extra_context: extra,
        blocked: false,
        label: None,
    };

    let result = filter.process_event(&proc, &event);

    assert!(result.is_some());
    assert_eq!(result.unwrap().blocked, true);
}

#[test]
fn test_dont_block_open_in_non_forbidden_folder() {
    let block_open = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_write as i64].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                vec!["/forbidden_folder".to_string()],
                StrMatchOp::Prefix,
                false,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::new(vec![block_open], None, None);
    let mut proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
    proc.add_created_path("/non_forbidden_folder/file.txt".to_string());
    proc.add_fd(
        5,
        EXTRA_PATHNAME,
        String::from("/non_forbidden_folder/file.txt"),
        0,
    );
    let mut regs = Regs::default();
    regs.syscall_id = native::SYS_write as u64;
    regs.regs[0] = 5; // some file descriptor, not stdin, stdout, or stderr

    let mut extra = HashMap::new();
    extra.insert(EXTRA_PATHNAME, "/not_forbidden_folder/file.txt".to_string());
    let event = SyscallEvent {
        id: regs.syscall_id,
        name: "write".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: regs.clone(),
        return_value: 0,
        stop_type: crate::syscall_event::SyscallStopType::Enter,
        extra_context: extra,
        blocked: false,
        label: None,
    };

    let result = filter.process_event(&proc, &event);

    assert!(result.is_some());
    assert_eq!(result.unwrap().blocked, false);
}

#[test]
fn test_dont_block_open_in_forbidden_folder_when_created_by_this_process() {
    let block_open = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_write as i64].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                vec!["/forbidden_folder".to_string()],
                StrMatchOp::Prefix,
                true,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::new(vec![block_open], None, None);
    let mut proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
    proc.add_created_path("/forbidden_folder/file.txt".to_string());
    proc.add_fd(
        5,
        EXTRA_PATHNAME,
        String::from("/forbidden_folder/file.txt"),
        0,
    );
    let mut regs = Regs::default();
    regs.syscall_id = native::SYS_write as u64;
    regs.regs[0] = 5; // some file descriptor, not stdin, stdout, or stderr

    let mut extra = HashMap::new();
    extra.insert(EXTRA_PATHNAME, "/forbidden_folder/file.txt".to_string());

    let event = SyscallEvent {
        id: regs.syscall_id,
        name: "write".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: regs.clone(),
        return_value: 0,
        stop_type: crate::syscall_event::SyscallStopType::Enter,
        extra_context: extra,
        blocked: false,
        label: None,
    };

    let result = filter.process_event(&proc, &event);

    assert!(result.is_some());
    assert_eq!(result.unwrap().blocked, false);
}
