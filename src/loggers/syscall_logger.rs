use crate::syscall_event::SyscallEvent;

pub(crate) trait SyscallLogger {
    fn log_event(&self, event: &SyscallEvent);
}
