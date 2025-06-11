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
