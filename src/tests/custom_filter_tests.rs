use std::collections::HashMap;

use nix::libc;
use syscall_numbers::native;

use crate::{
    FilteringLogger, TextLogger,
    filters::{
        path_matcher::{PathMatchOp, PathMatcher},
        syscall_filter::{FilterOutcome, SyscallFilter},
    },
    regs::Regs,
    syscall_common::EXTRA_PATHNAME,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
};

#[test]
fn test_block_open_in_forbidden_folder() {
    let block_open = SyscallFilter {
        syscall: [native::SYS_write as i64].into(),
        args: Default::default(),
        path_matcher: Some(PathMatcher::new(
            vec!["/forbidden_folder".to_string()],
            PathMatchOp::Prefix,
            false,
        )),
        flag_matcher: None,
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::<TextLogger>::new(vec![block_open], None, None);
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
        syscall: [native::SYS_write as i64].into(),
        args: Default::default(),
        path_matcher: Some(PathMatcher::new(
            vec!["/forbidden_folder".to_string()],
            PathMatchOp::Prefix,
            false,
        )),
        flag_matcher: None,
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::<TextLogger>::new(vec![block_open], None, None);
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
        syscall: [native::SYS_write as i64].into(),
        args: Default::default(),
        path_matcher: Some(PathMatcher::new(
            vec!["/forbidden_folder".to_string()],
            PathMatchOp::Prefix,
            true,
        )),
        flag_matcher: None,
        outcome: FilterOutcome {
            action: crate::filters::syscall_filter::FilterAction::Block(libc::ENOSYS),
            log: true,
            tag: Some("blocked_open".to_string()),
        },
    };

    let mut filter = FilteringLogger::<TextLogger>::new(vec![block_open], None, None);
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
