use crate::syscall_event::SyscallEvent;

pub(crate) type SyscallLogger = fn(event: &SyscallEvent);
