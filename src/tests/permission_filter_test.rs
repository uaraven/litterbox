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
