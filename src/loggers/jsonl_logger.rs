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

use std::collections;

use crate::{
    syscall_args::SyscallArgument,
    syscall_event::{SyscallEvent, SyscallStopType},
};

use super::syscall_logger::SyscallLogger;

#[derive(serde::Serialize, Debug)]
struct JsonEvent {
    pid: i32,
    name: String,
    syscall: u64,
    label: Option<String>,
    arguments: Vec<SyscallArgument>,
    return_value: i64,
    syscall_event: String,
    blocked: bool,
    extra_context: collections::HashMap<&'static str, String>,
}

#[derive(Default)]
pub(crate) struct JsonlLogger {}

impl SyscallLogger for JsonlLogger {
    fn log_event(&self, event: &SyscallEvent) {
        let event = JsonEvent {
            pid: event.pid as i32,
            name: event.name.clone(),
            syscall: event.id,
            label: event.label.clone(),
            arguments: event.arguments.clone(),
            return_value: event.return_value as i64,
            syscall_event: match event.stop_type {
                SyscallStopType::Enter => "enter".to_string(),
                SyscallStopType::Exit => "exit".to_string(),
            },
            blocked: event.blocked,
            extra_context: event.extra_context.clone(),
        };
        let content = serde_json::to_string(&event).unwrap();
        println!("{}", content);
    }
}
