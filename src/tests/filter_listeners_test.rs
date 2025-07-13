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
use std::{
    collections::{HashMap, HashSet},
    vec,
};

use crate::filters::address_matcher::AddressMatcher;
use crate::filters::syscall_filter::SyscallMatcher;
use crate::sandbox::sandbox_network::create_network_filter;
#[cfg(test)]
use crate::{
    filters::{
        context_matcher::ContextMatcher,
        flag_matcher::FlagMatcher,
        matcher::StrMatchOp,
        path_matcher::PathMatcher,
        syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
    },
    regs::Regs,
    syscall_common::{EXTRA_FLAGS, EXTRA_PATHNAME},
    syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType},
    trace_process::TraceProcess,
    FilteringLogger,
};
#[cfg(test)]
use nix::{libc::user_regs_struct, unistd::Pid};
#[cfg(test)]
use syscall_numbers::native;

#[cfg(test)]
fn fake_syscall_id(_pid: Pid, _regs: user_regs_struct, _new_id: u64) -> Result<(), nix::Error> {
    return Ok(());
}

#[cfg(test)]
fn make_test_event(id: u64, extra_path: Option<&str>) -> SyscallEvent {
    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    if let Some(path) = extra_path {
        extra_context.insert(crate::syscall_common::EXTRA_PATHNAME, path.to_string());
    }
    SyscallEvent {
        id,
        name: "syscall_name".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: Default::default(),
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: extra_context,
        blocked: false,
        label: None,
    }
}

#[test]
fn test_group_syscalls_in_filtering_logger() {
    let logger = FilteringLogger::new(create_network_filter(vec!["192.168."]), None, None);
    let connect_filter = logger.filters.get(&(native::SYS_connect as u64));
    assert!(connect_filter.is_some());
    assert_eq!(connect_filter.unwrap().len(), 3);
    let connect_filter = logger.filters.get(&(native::SYS_listen as u64));
    assert!(connect_filter.is_some());
    assert_eq!(connect_filter.unwrap().len(), 2);
}

#[test]
fn test_default_filtering_logger_primed() {
    let mut logger = FilteringLogger::default();
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let event = make_test_event(0, None);
    assert!(logger.primed);
    let result = logger.process_event(&proc, &event);
    assert!(result.is_some());
    assert!(logger.primed)
}

#[test]
fn test_trigger_event_blocks_until_primed() {
    let trigger = SyscallMatcher {
        syscall: HashSet::from([42]),
        args: vec![],
        context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
            vec!["/tmp/trigger".to_string()],
            StrMatchOp::Exact,
            false,
        ))),
        flag_matcher: None,
    };
    let mut logger = FilteringLogger::new(vec![], Some(trigger), None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    // Not primed, wrong syscall
    let event = make_test_event(1, Some("/tmp/trigger"));
    let result = logger.process_event(&proc, &event);
    assert!(result.is_some());
    assert!(!logger.primed);

    // Not primed, right syscall but wrong path
    let event = make_test_event(42, Some("/wrong/path"));
    let result = logger.process_event(&proc, &event);
    assert!(result.is_some());
    assert!(!logger.primed);

    // Priming event
    let event = make_test_event(42, Some("/tmp/trigger"));
    let result = logger.process_event(&proc, &event);
    assert!(result.is_some());
    assert!(logger.primed);

    // Now primed, all events go through filters
    let event = make_test_event(1, None);
    let result = logger.process_event(&proc, &event);
    assert!(result.is_some());
}

#[test]
fn test_filtering_logger_with_custom_filter() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [123].into(),
            args: Default::default(),
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let event = make_test_event(123, None);
    let result = logger.process_event(&proc, &event).unwrap();
    assert_eq!(result.label, Some("blocked".to_string()));
    assert!(result.blocked);
}

#[test]
fn test_filtering_logger_default_syscall_id_filters() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: HashSet::new(),
            args: Default::default(),
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            log: true,
            tag: Some("allowed".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let event = make_test_event(999, None);
    let result = logger.process_event(&proc, &event).unwrap();
    assert_eq!(result.label, Some("allowed".to_string()));
    assert!(!result.blocked);
}

#[test]
fn test_handle_filter_non_matching() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [123].into(),
            args: Default::default(),
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: None,
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let event = make_test_event(456, None);
    let result = logger.process_event(&proc, &event).unwrap();
    assert_eq!(result.label, None);
}

#[test]
fn test_handle_filter_matching_by_flag() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_openat].into(),
            args: Default::default(),
            context_matcher: None,
            flag_matcher: Some(FlagMatcher::new(vec!["O_CREAT".to_string()])),
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    extra_context.insert(EXTRA_FLAGS, "O_CREAT|O_RDONLY".to_string());
    let bad_event = SyscallEvent {
        id: native::SYS_openat as u64,
        name: "openat".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: vec![],
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: extra_context,
        blocked: false,
        label: None,
    };
    let result = logger.process_event(&proc, &bad_event).unwrap();
    assert_eq!(result.label, Some("blocked".to_string()));

    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    extra_context.insert(EXTRA_FLAGS, "O_RDONLY".to_string());
    let good_event = SyscallEvent {
        id: native::SYS_openat as u64,
        name: "openat".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: vec![],
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: extra_context,
        blocked: false,
        label: None,
    };
    let result = logger.process_event(&proc, &good_event).unwrap();
    assert_eq!(result.label, None);
}

#[test]
fn test_handle_filter_matching_by_path_prefix() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_openat].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                vec!["/tmp/".to_string()],
                StrMatchOp::Prefix,
                false,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    extra_context.insert(EXTRA_PATHNAME, "/tmp/somefile.txt".to_string());
    let bad_event = SyscallEvent {
        id: native::SYS_openat as u64,
        name: "openat".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: vec![],
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: extra_context,
        blocked: false,
        label: None,
    };
    let result = logger.process_event(&proc, &bad_event).unwrap();
    assert_eq!(result.label, Some("blocked".to_string()));

    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    extra_context.insert(EXTRA_PATHNAME, "/etc/somefile.txt".to_string());
    let good_event = SyscallEvent {
        id: native::SYS_openat as u64,
        name: "openat".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: vec![],
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: extra_context,
        blocked: false,
        label: None,
    };
    let result = logger.process_event(&proc, &good_event).unwrap();
    assert_eq!(result.label, None);
}

#[test]
fn test_handle_filter_with_filepath_on_event_without_filepath() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_openat].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                vec!["/tmp/".to_string()],
                StrMatchOp::Prefix,
                false,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let no_path_event = create_event_empty_extras(native::SYS_openat as u64);
    let result = logger.process_event(&proc, &no_path_event).unwrap();
    assert_eq!(result.blocked, false);
}

#[test]
fn test_handle_filter_with_addr_on_event_without_addr() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_connect].into(),
            args: Default::default(),
            context_matcher: Some(ContextMatcher::AddressMatcher(AddressMatcher::new(
                vec!["192.168.".to_string()],
                StrMatchOp::Prefix,
                None,
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let no_addr_event = create_event_empty_extras(native::SYS_connect as u64);
    let result = logger.process_event(&proc, &no_addr_event).unwrap();
    assert_eq!(result.blocked, false);
}

#[test]
fn test_handle_filter_with_flags_on_event_without_flags() {
    let filter = SyscallFilter {
        matcher: SyscallMatcher {
            syscall: [native::SYS_connect].into(),
            args: Default::default(),
            context_matcher: None,
            flag_matcher: Some(FlagMatcher::new(vec!["O_RDONLY".to_string()])),
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
    };
    let mut logger = FilteringLogger::new(vec![filter], None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));
    let no_path_event = create_event_empty_extras(native::SYS_openat as u64);
    let result = logger.process_event(&proc, &no_path_event).unwrap();
    assert_eq!(result.blocked, false);
}

fn create_event_empty_extras(syscall_id: u64) -> SyscallEvent {
    SyscallEvent {
        id: syscall_id,
        name: "openat".to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: vec![],
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context: HashMap::default(),
        blocked: false,
        label: None,
    }
}
