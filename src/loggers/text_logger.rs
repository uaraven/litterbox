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

use crate::syscall_event::{SyscallEvent, SyscallStopType};

use super::syscall_logger::SyscallLogger;

#[derive(Default)]
pub(crate) struct TextLogger {}

impl SyscallLogger for TextLogger {
    fn log_event(&self, event: &SyscallEvent) {
        let mut content = String::new();
        content.push_str(&format!("[{}] {} ({})", event.pid, event.name, event.id));
        if let Some(label) = &event.label {
            content.push_str(&format!(" |{}|", label));
        }
        content.push_str(" (");
        for arg in &event.arguments {
            content.push_str(&format!("{},", arg));
        }

        if event.arguments.len() > 0 {
            content.pop(); // Remove the last comma
        }
        match event.stop_type {
            SyscallStopType::Enter => {
                if event.blocked {
                    content.push_str(") -> (!)")
                } else {
                    content.push_str(")")
                }
            }
            SyscallStopType::Exit => {
                content.push_str(&format!(") -> {}", event.return_value as i64))
            }
        }
        if event.extra_context.len() > 0 {
            content.push_str(" {");
            for (key, value) in &event.extra_context {
                content.push_str(&format!("{}: '{}',", key, value));
            }
            content.pop(); // Remove the last comma
            content.push('}');
        }
        println!("{}", content);
    }
}
