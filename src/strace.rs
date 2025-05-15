use std::collections::HashMap;

use nix::errno::Errno;
use nix::libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::{ptrace, signal};
use nix::unistd::Pid;

use crate::syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType};

/// A struct to hold the additional data for a file descriptor
/// This structure is populated by the syscall that creates the file descriptor
/// and is used to provide additional information about the file descriptor
/// at the point of use. For example, the filepath associated with the file descriptor
/// during `sys_open` call can be retrieved from this structure during the `sys_read` call.
#[derive(Debug, Clone)]
pub struct FdData {
    pub name: &'static str,
    pub value: String,
}

pub struct TraceProcess {
    pid: Pid,
    last_syscall: SyscallEvent,
    expected_stop_type: SyscallStopType,
    fd_map: HashMap<i64, FdData>,
}

impl TraceProcess {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            last_syscall: SyscallEvent::fake_event(),
            expected_stop_type: SyscallStopType::Enter,
            fd_map: HashMap::new(),
        }
    }

    pub fn copy_from(other: &TraceProcess, new_pid: Pid) -> Self {
        Self {
            pid: new_pid,
            last_syscall: SyscallEvent::fake_event(),
            expected_stop_type: SyscallStopType::Enter,
            fd_map: other.fd_map.clone(),
        }
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    // Get the last syscall event
    // If the current syscall ID is not the same as the last syscall ID, return None
    pub fn get_last_syscall(&self, current_syscall_id: u64) -> Option<&SyscallEvent> {
        if self.last_syscall.id != current_syscall_id {
            return None;
        } else {
            Some(&self.last_syscall)
        }
    }

    pub fn set_last_syscall(&mut self, syscall: &SyscallEvent) {
        self.last_syscall = syscall.clone();
    }

    pub fn add_fd(&mut self, fd: i64, name: &'static str, value: String) {
        self.fd_map.insert(fd, FdData { name, value });
    }

    pub fn get_fd(&self, fd: i64) -> Option<&FdData> {
        self.fd_map.get(&fd)
    }

    pub fn remove_fd(&mut self, fd: i64) {
        self.fd_map.remove(&fd);
    }

    pub fn set_current_stop_type(&mut self, stop_type: SyscallStopType) {
        self.expected_stop_type = match stop_type {
            SyscallStopType::Enter => SyscallStopType::Exit,
            SyscallStopType::Exit => SyscallStopType::Enter,
        };
    }

    pub fn is_entry(&self, syscall_id: u64) -> bool {
        match self.expected_stop_type {
            SyscallStopType::Enter => true,
            SyscallStopType::Exit => {
                if self.last_syscall.id == syscall_id {
                    false
                } else {
                    // if we thought that previous syscall-stop was on entry and now we see different syscall id
                    // that means that the previous stop was actually on exit and now is on entry
                    true
                }
            }
        }
    }
}

pub struct TraceContext<F: SyscallEventListener> {
    pid: Pid,
    listener: Option<F>,
    processes: HashMap<Pid, TraceProcess>,
}

impl<F: SyscallEventListener> TraceContext<F> {
    pub fn new(pid: Pid, listener: Option<F>) -> Self {
        Self {
            pid,
            listener,
            processes: HashMap::new(),
        }
    }

    pub fn trace_process(&mut self) {
        waitpid(self.pid, None).expect("Failed to wait for child");
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )
        .expect("Failed to set ptrace options");
        ptrace::syscall(self.pid, None).expect("Failed to continue tracee executuion");
        self.processes.insert(self.pid, TraceProcess::new(self.pid));
        let mut is_entry = true;
        loop {
            let mut restart_pid = self.pid;
            let mut inject_signal: Option<signal::Signal> = None;
            // consider flag WaitPidFlag::WNOHANG for busy cycle without waitpid blocking
            let status = waitpid(Pid::from_raw(-1), None);
            if let Ok(wait_status) = status {
                match wait_status {
                    WaitStatus::Exited(pid, exit_code) => {
                        println!("Process {} exited with code {}", pid, exit_code);
                        self.processes.remove(&pid);
                        if pid == self.pid {
                            break;
                        } else {
                            continue;
                        }
                    }
                    WaitStatus::Signaled(pid, _, _) => {
                        self.processes.remove(&pid);
                        println!("Process {} was terminated.", pid);
                        continue;
                    }
                    WaitStatus::PtraceEvent(pid, _, event) => {
                        restart_pid = pid;
                        // PTRACE_EVENT stop
                        if event == PTRACE_EVENT_EXEC {
                            let event_data: i32 = ptrace::getevent(pid)
                                .unwrap()
                                .try_into()
                                .expect("Failed to convert event to i32");
                            let new_pid = Pid::from_raw(event_data);
                            println!("Exec'ing new  process with pid={} exec", new_pid);
                            let new_process = TraceProcess::new(new_pid);
                            self.processes.clear();
                            self.processes.insert(new_pid, new_process);
                        } else if event == PTRACE_EVENT_CLONE
                            || event == PTRACE_EVENT_FORK
                            || event == PTRACE_EVENT_VFORK
                        {
                            let event_data: i32 = ptrace::getevent(pid)
                                .unwrap()
                                .try_into()
                                .expect("Failed to convert event to i32");
                            let child_pid = Pid::from_raw(event_data);
                            if child_pid != self.pid {
                                println!("Child process with pid={} forked", child_pid);
                                let parent = self.processes.get_mut(&pid).expect(
                                    format!("No process with pid {} is being traced", pid).as_str(),
                                );
                                let child_process = TraceProcess::copy_from(&parent, child_pid);
                                self.processes.insert(child_pid, child_process);
                            } else {
                                println!("Process {} started child process {}", pid, child_pid);
                            }
                        }
                    }
                    WaitStatus::PtraceSyscall(pid) => {
                        restart_pid = pid;
                        let process = self.processes.get_mut(&pid).expect(
                            format!("No process with pid {} is being traced", pid).as_str(),
                        );
                        let regs = ptrace::getregs(pid).unwrap();
                        let syscall_event = SyscallEvent::from_syscall(process, regs);
                        process.set_current_stop_type(syscall_event.stop_type);

                        if let Some(event_listener) = &mut self.listener {
                            match event_listener.process_event(&syscall_event) {
                                Some(new_event) => {
                                    process.set_last_syscall(&new_event);
                                }
                                None => {
                                    process.set_last_syscall(&syscall_event);
                                }
                            }
                        }
                    }
                    WaitStatus::Stopped(pid, signal) => {
                        restart_pid = pid;
                        // signal-delivery-stop, we will restart the process with the injected signal
                        inject_signal = Some(signal);
                        match signal {
                            Signal::SIGSTOP
                            | Signal::SIGTSTP
                            | Signal::SIGTTIN
                            | Signal::SIGTTOU => {
                                match ptrace::getsiginfo(pid) {
                                    Ok(siginfo) => {
                                        println!("Pid:{} SIGSTOP signal: {:?}", pid, siginfo);
                                    }
                                    Err(e) => {
                                        if e == Errno::EINVAL {
                                            // group-stop
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            } else {
                println!("Error waiting for child process");
                break;
            }

            match ptrace::syscall(restart_pid, inject_signal) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error continuing tracee {}: {}", self.pid, e);
                }
            }

            is_entry = !is_entry;
        }
    }
}
