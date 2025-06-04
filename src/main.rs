mod fd_utils;
mod filter_listener;
mod filters;
mod flags;
mod loggers;
mod preconfigured;
mod regs;
mod simple_logger;
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

use filter_listener::FilteringLogger;
use loggers::text_logger::TextLogger;
use nix::sys::ptrace;
use nix::unistd::{ForkResult, fork};
use preconfigured::permissive::permissive_filters;

use std::env;

fn main() {
    let mut args = env::args().skip(1);

    // let opt_cfgs = vec![
    //     OptCfg::with([
    //         names(&["filter", "f"]),
    //         has_arg(true),
    //         default(&["restrictive"]),
    //         arg_in_help("<permissive|restrictive>"),
    //         desc("This is description of foo-bar."),
    //     ]),
    //     OptCfg::with([
    //         names(&["o", "output"]),
    //         has_arg(true),
    //         defaults(&["output.txt"]),
    //         desc("File to which the syscalls will be logged"),
    //         arg_in_help("<file_name>"),
    //     ]),
    // ];

    // let cmd = match Cmd::new() {
    //     Ok(cmd) => cmd,
    //     Err(e) => {
    //         eprintln!("Error parsing command line arguments: {}", e);
    //         std::process::exit(1);
    //     }
    // };
    // cmd.parse_args(&args, &opt_cfgs);
    // let args = cmd.get_args();
    // let opts = cmd.get_opts();

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

            let logger = TextLogger {};
            let mut filter_logger = permissive_filters(logger);

            let mut tracer = strace::TraceContext::new(child, Some(filter_logger));

            tracer.trace_process();
        }
        Err(e) => {
            eprintln!("Failed to start app {}", e);
        }
    }
    // Spawn the command
}
