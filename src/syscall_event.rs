use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::get_syscall_name;
use crate::syscall_parser::syscall_parser;
use crate::trace_process::TraceProcess;
use nix::libc::{self, user_regs_struct};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::ffi::c_void;

use nix::errno::Errno;
use std::fmt;

pub type ExtraData = HashMap<&'static str, String>;

#[derive(Debug, Clone, Copy)]
pub enum SyscallStopType {
    Enter,
    Exit,
}

#[derive(Debug, Clone)]
pub struct SyscallEvent {
    pub id: u64,
    pub name: String,
    pub pid: i32,
    pub arguments: Vec<SyscallArgument>,
    pub regs: Regs,
    pub return_value: u64,
    pub stop_type: SyscallStopType,
    pub extra_context: ExtraData,
    pub blocked: bool,
}

impl SyscallEvent {
    pub fn new(proc: &TraceProcess, arguments: Vec<SyscallArgument>, regs: &Regs) -> SyscallEvent {
        let syscall_name = get_syscall_name(regs.syscall_id);
        let is_entry = proc.is_entry(regs.syscall_id);
        SyscallEvent {
            id: regs.syscall_id,
            name: syscall_name,
            pid: proc.get_pid().as_raw().into(),
            arguments: arguments,
            regs: regs.clone(),
            return_value: regs.return_value,
            stop_type: if is_entry {
                SyscallStopType::Enter
            } else {
                SyscallStopType::Exit
            },
            extra_context: Default::default(),
            blocked: false,
        }
    }
    pub fn new_with_extras(
        proc: &TraceProcess,
        arguments: Vec<SyscallArgument>,
        regs: &Regs,
        extras: ExtraData,
    ) -> SyscallEvent {
        let syscall_name = get_syscall_name(regs.syscall_id);
        let is_entry = proc.is_entry(regs.syscall_id);
        SyscallEvent {
            id: regs.syscall_id,
            name: syscall_name,
            pid: proc.get_pid().as_raw().into(),
            arguments: arguments,
            regs: regs.clone(),
            return_value: regs.return_value,
            stop_type: if is_entry {
                SyscallStopType::Enter
            } else {
                SyscallStopType::Exit
            },
            extra_context: extras,
            blocked: false,
        }
    }
    pub fn fake_event() -> SyscallEvent {
        SyscallEvent {
            id: 0xffff_ffff_ffff_ffff,
            name: String::new(),
            pid: 0,
            arguments: Vec::new(),
            regs: Regs::default(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: HashMap::new(),
            blocked: false,
        }
    }

    pub fn from_syscall(process: &mut TraceProcess, uregs: user_regs_struct) -> SyscallEvent {
        let rr = Regs::from_regs(&uregs);
        let parser_func = syscall_parser(rr.syscall_id);
        parser_func(process, rr)
    }

    pub fn block_syscall(&self, error_code: Option<i32>) -> SyscallEvent {
        match self.stop_type {
            SyscallStopType::Enter => {
                let arch_regs = self.regs.to_regs();
                // let's set the syscall ID to -1
                if let Err(e) =
                    self.set_syscall_id(Pid::from_raw(self.pid), arch_regs, 0xffff_ffff_ffff_ffff)
                {
                    eprintln!("Error setting registers: {}", e);
                    return self.clone();
                } else {
                    return SyscallEvent {
                        blocked: true,
                        ..self.clone()
                    };
                }
            }
            SyscallStopType::Exit => {
                let err = error_code.unwrap_or(-libc::ENOSYS as i32) as u64;
                let mut regs = self.regs.clone();
                regs.return_value = err;
                let arch_regs = regs.to_regs();
                if let Err(e) = ptrace::setregs(Pid::from_raw(self.pid), arch_regs) {
                    eprintln!("Error setting registers: {}", e);
                    return self.clone();
                } else {
                    return SyscallEvent {
                        blocked: true,
                        ..self.clone()
                    };
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn set_syscall_id(
        &self,
        pid: Pid,
        arch_regs: user_regs_struct,
        syscall_id: u64,
    ) -> Result<(), nix::Error> {
        let mut regs = arch_regs;
        regs.orig_rax = syscall_id;
        ptrace::setregs(pid, regs)
    }

    /// On ARM64, we need to set the syscall ID in a different way, we use different register set, NT_ARM_SYSTEM_CALL
    /// to set the syscall ID. Usual ptrace::setregs will not work.
    #[cfg(target_arch = "aarch64")]
    fn set_syscall_id(
        &self,
        pid: Pid,
        _arch_regs: user_regs_struct,
        syscall_id: u64,
    ) -> Result<(), nix::Error> {
        const PTRACE_SETREGSET: usize = 0x4205;
        const NT_ARM_SYSTEM_CALL: usize = 0x404;

        let regs = libc::iovec {
            iov_base: &syscall_id as *const _ as *mut c_void,
            iov_len: std::mem::size_of_val(&syscall_id),
        };
        let res = unsafe {
            libc::ptrace(
                PTRACE_SETREGSET as _,
                libc::pid_t::from(pid.as_raw()),
                NT_ARM_SYSTEM_CALL,
                &regs as *const _ as *const c_void,
            )
        };
        Errno::result(res)?;
        Ok(())
    }
}
impl fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut content = String::new();
        content.push_str(&format!("[{}] {} ({}) (", self.pid, self.name, self.id));
        for arg in &self.arguments {
            content.push_str(&format!("{},", arg));
        }
        if self.arguments.len() > 0 {
            content.pop(); // Remove the last comma
        }
        match self.stop_type {
            SyscallStopType::Enter => content.push_str(")"),
            SyscallStopType::Exit => {
                content.push_str(&format!(") -> {}", self.return_value as i64))
            }
        }
        if self.extra_context.len() > 0 {
            content.push_str(" {");
            for (key, value) in &self.extra_context {
                content.push_str(&format!("{}: '{}',", key, value));
            }
            content.pop(); // Remove the last comma
            content.push('}');
        }
        write!(f, "{}", content)
    }
}

pub trait SyscallEventListener {
    fn process_event(&mut self, event: &SyscallEvent) -> Option<SyscallEvent>;
}
