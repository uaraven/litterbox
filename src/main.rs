mod regs;
mod scan_events;
mod simple_logger;
mod strace;
mod syscall_args;
mod syscall_common;
mod syscall_event;
mod syscall_ids;
mod syscall_parser;
mod syscall_parsers_file;
mod syscall_parsers_process;
mod syscall_parsers_socket;

use nix::sys::ptrace;
use nix::unistd::{ForkResult, fork};
use simple_logger::logging_listener;

use std::env;

fn main() {
    let mut args = env::args().skip(1);

    // First argument is the program name to run
    let program = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("Usage: runner <program> [args...]");
            std::process::exit(1);
        }
    };

    // The rest are arguments to pass to that program
    let program_args: Vec<String> = args.collect();

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Failed to trace me");
            let err = exec::Command::new(program).args(&program_args).exec();
            println!("Error: {}", err);
        }
        Ok(ForkResult::Parent { child }) => {
            let mut tracer = strace::TraceContext::new(child, Some(logging_listener));

            tracer.trace_process();
        }
        Err(e) => {
            eprintln!("Failed to start app {}", e);
        }
    }
    // Spawn the command
}
