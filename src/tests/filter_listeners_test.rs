#[cfg(test)]
use std::{
    collections::{HashMap, HashSet},
    vec,
};

#[cfg(test)]
use crate::{
    FilteringLogger,
    filter_listener::SyscallFilterTrigger,
    filters::{
        event_matcher::ContextMatcher,
        flag_matcher::FlagMatcher,
        matcher::StrMatchOp,
        path_matcher::PathMatcher,
        syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
    },
    regs::Regs,
    syscall_common::{EXTRA_FLAGS, EXTRA_PATHNAME},
    syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType},
    trace_process::TraceProcess,
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
    let trigger = SyscallFilterTrigger {
        syscall_id: 42,
        file_path: Some("/tmp/trigger".to_string()),
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
        syscall: [123].into(),
        args: Default::default(),
        context_matcher: None,
        flag_matcher: None,
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
        syscall: HashSet::new(),
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            log: true,
            tag: Some("allowed".to_string()),
        },
        args: Default::default(),
        context_matcher: None,
        flag_matcher: None,
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
        syscall: [123].into(),
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: None,
        },
        args: Default::default(),
        context_matcher: None,
        flag_matcher: None,
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
        syscall: [native::SYS_openat].into(),
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
        args: Default::default(),
        context_matcher: None,
        flag_matcher: Some(FlagMatcher::new(vec!["O_CREAT".to_string()])),
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
        syscall: [native::SYS_openat].into(),
        outcome: FilterOutcome {
            action: FilterAction::Block(1),
            log: false,
            tag: Some("blocked".to_string()),
        },
        args: Default::default(),
        context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
            vec!["/tmp/".to_string()],
            StrMatchOp::Prefix,
            false,
        ))),
        flag_matcher: None,
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
