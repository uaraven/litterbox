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
use crate::{
    loggers::text_logger::TextLogger,
    preconfigured::restrictive,
    regs::Regs,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
};
#[cfg(test)]
use syscall_numbers::native;

#[test]
fn test_restrictive_filter_allow_stdout() {
    let logger = TextLogger {};
    let mut filter = restrictive::restrictive_filters(Box::new(logger));
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
    let mut filter = restrictive::restrictive_filters(Box::new(TextLogger {}));
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
