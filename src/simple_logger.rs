use crate::syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType};
use crate::syscall_ids::*;
use syscall_numbers::native;

const LOG_ON_ENTER: [i64; 6] = [
    native::SYS_clone,
    native::SYS_clone3,
    SYS_FORK,
    SYS_VFORK,
    native::SYS_execve,
    native::SYS_execveat,
]; // Example syscall IDs

const LOGGABLE_SYSCALLS: [i64; 13] = [
    SYS_OPEN,
    native::SYS_openat,
    native::SYS_write,
    native::SYS_read,
    native::SYS_clone,
    native::SYS_clone3,
    native::SYS_execve,
    native::SYS_execveat,
    native::SYS_socket,
    native::SYS_connect,
    native::SYS_listen,
    SYS_FORK,
    SYS_VFORK,
]; // Example syscall IDs

fn is_loggable(syscall_id: i64) -> bool {
    LOGGABLE_SYSCALLS.contains(&syscall_id)
}

fn is_log_on_entry(syscall_id: i64) -> bool {
    LOG_ON_ENTER.contains(&syscall_id)
}

pub struct SimpleLogger {}

impl SyscallEventListener for SimpleLogger {
    fn process_event(&mut self, event: &SyscallEvent) -> Option<SyscallEvent> {
        if !is_loggable(event.id as i64) {
            return Some(event.clone());
        }
        match event.stop_type {
            SyscallStopType::Exit => {
                println!("{}", event);
            }
            SyscallStopType::Enter => {
                if is_log_on_entry(event.id as i64) {
                    println!("{} ...", event);
                }
            }
        }
        return Some(event.clone());
    }
}
