use crate::syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType};
#[cfg(target_arch = "aarch64")]
use syscall_numbers::aarch64;
#[cfg(target_arch = "x86_64")]
use syscall_numbers::x86_64;

use syscall_numbers::native;

const LOG_ON_ENTER: [i64; 2] = [native::SYS_execve, native::SYS_execveat]; // Example syscall IDs

#[cfg(target_arch = "aarch64")]
const LOGGABLE_SYSCALLS: [i64; 10] = [
    aarch64::SYS_openat,
    aarch64::SYS_write,
    aarch64::SYS_read,
    aarch64::SYS_clone,
    aarch64::SYS_clone3,
    aarch64::SYS_execve,
    aarch64::SYS_execveat,
    aarch64::SYS_socket,
    aarch64::SYS_connect,
    aarch64::SYS_listen,
]; // Example syscall IDs

#[cfg(target_arch = "x86_64")]
const LOGGABLE_SYSCALLS: [i64; 10] = [
    x86_64::SYS_open,
    x86_64::SYS_openat,
    x86_64::SYS_write,
    x86_64::SYS_read,
    x86_64::SYS_clone,
    x86_64::SYS_clone3,
    x86_64::SYS_execve,
    x86_64::SYS_execveat,
    x86_64::SYS_socket,
    x86_64::SYS_connect,
    x86_64::SYS_listen,
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
