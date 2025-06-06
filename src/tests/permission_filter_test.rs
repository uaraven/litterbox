#[cfg(test)]
use crate::{
    loggers::text_logger::TextLogger,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
};

#[test]
fn test_permissive_filter() {
    let logger = TextLogger {};
    let mut filter = crate::preconfigured::permissive::permissive_filters(Box::new(logger));
    let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

    let event = SyscallEvent {
        id: 10,
        name: "test_syscall".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: crate::regs::Regs::default(),
        return_value: 0,
        stop_type: crate::syscall_event::SyscallStopType::Enter,
        extra_context: Default::default(),
        blocked: false,
        label: None,
    };

    let result = filter.process_event(&proc, &event);

    assert!(result.is_some());
    assert_eq!(result.unwrap().blocked, false);
}
