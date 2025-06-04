#[cfg(test)]
use syscall_numbers::native;

#[cfg(test)]
use crate::{
    loggers::text_logger::TextLogger,
    regs::Regs,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
};

#[test]
fn test_restrictive_filter_allow_stdout() {
    let logger = TextLogger {};
    let mut filter = crate::preconfigured::restrictive::restrictive_filters(logger);
    let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
    let mut regs = Regs::default();
    regs.syscall_id = native::SYS_write as u64;
    regs.regs[0] = 1; // STDOUT file descriptor

    let event = SyscallEvent {
        id: regs.syscall_id,
        name: "write".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: regs.clone(),
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

#[test]
fn test_restrictive_filter_disallow_file_write() {
    let mut filter = crate::preconfigured::restrictive::restrictive_filters(TextLogger {});
    let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));
    let mut regs = Regs::default();
    regs.syscall_id = native::SYS_write as u64;
    regs.regs[0] = 5; // some file descriptor, not stdin, stdout, or stderr

    let event = SyscallEvent {
        id: regs.syscall_id,
        name: "write".to_string(),
        pid: 1000,
        set_syscall_id: |_, _, _| Ok(()),
        arguments: Default::default(),
        regs: regs.clone(),
        return_value: 0,
        stop_type: crate::syscall_event::SyscallStopType::Enter,
        extra_context: Default::default(),
        blocked: false,
        label: None,
    };

    let result = filter.process_event(&proc, &event);

    assert!(result.is_some());
    assert_eq!(result.unwrap().blocked, true);
}
