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
use crate::parsers::syscall_parser::syscall_parser;
use crate::regs::Regs;
use crate::syscall_args::SyscallArgument;
use crate::syscall_common::{
    get_syscall_name, EXTRA_ADDR, EXTRA_CWD, EXTRA_DIRFD, EXTRA_FLAGS, EXTRA_PATHNAME,
};
use crate::trace_process::{set_syscall_id, SetSyscallId, TraceProcess};
use nix::libc::{self, user_regs_struct};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::path::PathBuf;

use std::fmt;

pub type ExtraData = HashMap<&'static str, String>;

/// returns the absolute path of the file, if available in the event's extras
/// This function will check if the event originates from a *at syscall, and if so,
/// it'll use the dirfd to resolve the absolute path of the file.
pub(crate) fn get_abs_filepath_from_extra(extra: &ExtraData) -> Option<String> {
    let pathname = match extra.get(EXTRA_PATHNAME) {
        Some(pathname) => pathname,
        None => return None,
    };
    let dir = match extra.get(EXTRA_DIRFD) {
        Some(pathname) => pathname,
        None => match extra.get(EXTRA_CWD) {
            Some(pathname) => pathname,
            None => "",
        },
    };
    let mut abs_path = PathBuf::new();
    if !dir.is_empty() {
        abs_path.push(dir);
    }
    if !pathname.is_empty() {
        abs_path.push(pathname);
    }
    Some(abs_path.to_string_lossy().to_string())
}

#[derive(Debug, Clone, Copy)]
pub enum SyscallStopType {
    Enter,
    Exit,
}

#[derive(Debug, Clone)]
pub struct SyscallEvent {
    pub id: u64,
    pub name: String,
    pub set_syscall_id: SetSyscallId,
    pub pid: i32,
    pub arguments: Vec<SyscallArgument>,
    pub regs: Regs,
    pub return_value: u64,
    pub stop_type: SyscallStopType,
    pub extra_context: ExtraData,
    pub blocked: bool,
    pub label: Option<String>,
}

impl SyscallEvent {
    pub fn new(proc: &TraceProcess, arguments: Vec<SyscallArgument>, regs: &Regs) -> SyscallEvent {
        let syscall_name = get_syscall_name(regs.syscall_id);
        let is_entry = proc.is_entry(regs.syscall_id);
        SyscallEvent {
            id: regs.syscall_id,
            name: syscall_name,
            set_syscall_id: proc.set_syscall_id,
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
            label: None,
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
            set_syscall_id: proc.set_syscall_id,
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
            label: None,
        }
    }
    pub fn empty_event() -> SyscallEvent {
        SyscallEvent {
            id: 0xffff_ffff_ffff_ffff,
            name: String::new(),
            set_syscall_id: set_syscall_id,
            pid: 0,
            arguments: Vec::new(),
            regs: Regs::default(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: HashMap::new(),
            blocked: false,
            label: None,
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
                    (self.set_syscall_id)(Pid::from_raw(self.pid), arch_regs, 0xffff_ffff_ffff_ffff)
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
                let err = (-error_code.unwrap_or(libc::ENOSYS as i32)) as u64;
                let mut regs = self.regs.clone();
                regs.return_value = err;
                let arch_regs = regs.to_regs();
                if let Err(e) = ptrace::setregs(Pid::from_raw(self.pid), arch_regs) {
                    eprintln!("Error setting registers: {}", e);
                    return self.clone();
                } else {
                    return SyscallEvent {
                        blocked: true,
                        regs: regs,
                        return_value: err,
                        ..self.clone()
                    };
                }
            }
        }
    }

    /// returns the absolute path of the file, if available in the event's extras
    /// This function will check if the event originates from a *at syscall, and if so,
    /// it'll use the dirfd to resolve the absolute path of the file.
    pub fn get_abs_filepath(&self) -> Option<String> {
        get_abs_filepath_from_extra(&self.extra_context)
    }

    pub fn get_extras_pathname(&self) -> Option<&String> {
        self.extra_context.get(EXTRA_PATHNAME)
    }
    pub fn get_extras_addr(&self) -> Option<&String> {
        self.extra_context.get(EXTRA_ADDR)
    }

    pub fn get_extras_flags(&self) -> Option<&String> {
        self.extra_context.get(EXTRA_FLAGS)
    }
}

impl fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut content = String::new();
        content.push_str(&format!("[{}] {} ({})", self.pid, self.name, self.id));
        if self.label.is_some() {
            content.push_str(&format!(" |{}|", self.label.as_ref().unwrap()));
        }
        content.push_str(" (");
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
    fn process_event(&mut self, proc: &TraceProcess, event: &SyscallEvent) -> Option<SyscallEvent>;
}
