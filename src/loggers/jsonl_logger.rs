use crate::syscall_event::{SyscallEvent, SyscallStopType};

use super::syscall_logger::SyscallLogger;

#[derive(Default)]
pub(crate) struct JsonlLogger {}

impl SyscallLogger for JsonlLogger {
    fn log_event(&self, event: &SyscallEvent) {
        let mut content = String::new();
        content.push_str(&format!("[{}] {} ({})", event.pid, event.name, event.id));
        if event.label.is_some() {
            content.push_str(&format!(" |{}|", event.label.as_ref().unwrap()));
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
