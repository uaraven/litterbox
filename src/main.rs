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
mod cli_args;
mod fd_utils;
mod filter_listener;
mod filter_loader;
mod filters;
mod flags;
mod loggers;
mod preconfigured;
mod regs;
mod strace;
mod syscall_args;
mod syscall_common;
mod syscall_event;
mod syscall_parser;
mod syscall_parsers_file;
mod syscall_parsers_process;
mod syscall_parsers_socket;
mod trace_process;

mod tests;

use clap::Parser;
use cli_args::Cli;
use filter_listener::FilteringLogger;
use loggers::text_logger::TextLogger;
use nix::sys::ptrace;
use nix::unistd::{ForkResult, fork};

use crate::filter_loader::filters_from_args;

fn main() {
    let cli = Cli::parse();

    let program = match cli.prog.iter().next() {
        Some(p) => p,
        None => {
            eprintln!("Usage: litterbox [options...] <program> [args...]");
            std::process::exit(1);
        }
    };

    // The rest are arguments to pass to that program
    // let program_args: Vec<String> = args.collect();
    let program_args = cli
        .prog
        .iter()
        .skip(1)
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let pid = std::process::id();
            println!("Child process PID: {}", pid);
            ptrace::traceme().expect("Failed to trace child process");
            println!("Starting child process: {}", program);
            let err = exec::Command::new(program).args(&program_args).exec();
            println!("Error: {}", err);
        }
        Ok(ForkResult::Parent { child }) => {
            let pid = std::process::id();
            println!("Parent process PID: {}", pid);

            let filter_logger = match filters_from_args(cli) {
                Ok(logger) => logger,
                Err(e) => {
                    eprintln!("Error initializing filters: {}", e.msg);
                    std::process::exit(1);
                }
            };

            let mut tracer = strace::TraceContext::new(child, Some(filter_logger));

            tracer.trace_process();
        }
        Err(e) => {
            eprintln!("Failed to start app {}", e);
        }
    }
    // Spawn the command
}
