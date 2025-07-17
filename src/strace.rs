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
use std::collections::HashMap;

use nix::errno::Errno;
use nix::libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::sys::{ptrace, signal};
use nix::unistd::Pid;
use crate::regs::Regs;
use crate::syscall_common::BLOCKED_SYSCALL_ID;
use crate::syscall_event::{SyscallEvent, SyscallEventListener};
use crate::trace_process::TraceProcess;

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
        ptrace::syscall(self.pid, None).expect("Failed to continue tracee execution");
        self.processes.insert(self.pid, TraceProcess::new(self.pid));
        let mut is_entry = true;
        loop {
            let mut restart_pid = self.pid;
            let mut inject_signal: Option<Signal> = None;
            // consider flag WaitPidFlag::WNOHANG for busy cycle without waitpid blocking
            let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL));
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
                            // remove all other processes from the list
                            let mut pids_to_remove = Vec::new();
                            for pid in self.processes.keys() {
                                if *pid != new_pid {
                                    pids_to_remove.push(*pid);
                                }
                            }
                            for pid in pids_to_remove {
                                self.processes.remove(&pid);
                            }
                            if let Some(process) = self.processes.get_mut(&pid) {
                                process.clear_closed_fds();
                            }
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
                                if let Some(parent) = self.processes.get_mut(&pid) {
                                    let child_process = TraceProcess::clone_process(&parent, child_pid);
                                    self.processes.insert(child_pid, child_process);
                                } else {
                                    eprintln!("Failed to find parent pid: {} for child pid: {}", pid, child_pid);
                                }
                            } else {
                                println!("Process {} started child process {}", pid, child_pid);
                            }
                        }
                    }
                    WaitStatus::PtraceSyscall(pid) => {
                        restart_pid = pid;
                        if let Some(process) = self.processes.get_mut(&pid) {
                            let mut regs = ptrace::getregs(pid).unwrap();
                            let mut rr = Regs::from_regs(&regs);
                            let syscall_event = if rr.syscall_id == BLOCKED_SYSCALL_ID && !is_entry {
                                // this is exit from the blocked syscall
                                // replace error in syscall_id with the last syscall id for this process
                                rr.syscall_id = process.get_previous_syscall().regs.syscall_id;
                                println!("Got response to a blocked syscall {:?}", rr);
                                regs = rr.to_regs();
                                let mut syscall_event = SyscallEvent::from_syscall(process, regs);
                                syscall_event = syscall_event.block_syscall(Some(-1));
                                syscall_event
                            } else {
                                SyscallEvent::from_syscall(process, regs)
                            };
                            process.set_current_stop_type(syscall_event.stop_type);

                            if let Some(event_listener) = &mut self.listener {
                                match event_listener.process_event(process, &syscall_event) {
                                    Some(new_event) => {
                                        process.set_last_syscall(&new_event);
                                    }
                                    None => {
                                        process.set_last_syscall(&syscall_event);
                                    }
                                }
                            }
                        } else {
                            let regs = ptrace::getregs(pid).unwrap();
                            eprintln!("Received syscall for unknown pid {}, ignoring. Regs: {:?}", pid, regs)
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
                                        println!("Pid:{}, self.pid: {}, SIGSTOP signal: {:?}", pid, self.pid, siginfo);
                                    }
                                    Err(e) => {
                                        if e == Errno::EINVAL {
                                            // group-stop
                                        }
                                    }
                                }
                            }
                            _ => {
                                println!("Pid:{}, self.pid: {}, unknown signal: {:?}", pid, self.pid, signal);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                eprintln!("Error waiting for child process");
                break;
            }

            match ptrace::syscall(restart_pid, inject_signal) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error continuing tracee {}: {}", self.pid, e);
                }
            }

            is_entry = !is_entry;
        }
    }
}
