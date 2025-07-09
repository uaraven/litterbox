# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Litterbox is a sandboxing and syscall tracing tool written in Rust, designed for analyzing potentially malicious applications in a controlled environment. It provides syscall filtering, blocking, and logging capabilities similar to `strace` but with enhanced security features.

## Architecture

### Core Components

- **Main Entry Point** (`src/main.rs`): Handles process forking and sets up ptrace for syscall monitoring
- **CLI Arguments** (`src/cli_args.rs`): Defines command-line interface using clap with support for sandbox mode, filtering, and logging options
- **Filter System** (`src/filters/`): Modular filtering system supporting syscall name, path, address, and flag-based matching
- **Logging System** (`src/loggers/`): Supports text and JSONL output formats for syscall events
- **Syscall Parsing** (`src/syscall_parsers_*/`): Architecture-specific syscall argument parsing and interpretation
- **Sandbox Implementation** (`src/sandbox/`): Provides preconfigured security profiles (restrictive, permissive, default)

### Key Design Patterns

- **Modular Filter Architecture**: Filters are composable and support complex matching conditions defined in JSON
- **Process Tracing**: Uses ptrace to monitor child processes and intercept syscalls
- **File Descriptor Tracking**: Maintains mappings between file descriptors and paths/addresses for context-aware filtering
- **Cross-Platform Support**: Separate syscall definitions for x86_64 and aarch64 architectures

## Common Commands

### Building and Testing
```bash
# Build the project
cargo build

# Build optimized release version
cargo build --release

# Run tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

### Running Litterbox
```bash
# Basic sandbox mode (default)
cargo run -- /path/to/program

# Custom filter configuration
cargo run -- --filter /path/to/filter.json /path/to/program

# Text output with specific permissions
cargo run -- --allow-write /tmp --allow-connect 192.168.1.0/24 /path/to/program

# JSONL output format
cargo run -- --format jsonl /path/to/program
```

## Filter Configuration

Filters are defined in JSON format with the following structure:
- **matcher**: Defines conditions (syscall names, paths, addresses, flags)
- **outcome**: Specifies action (Allow/Block), error codes, tags, and logging

See `docs/filters.md` for detailed filter syntax and examples.

## Development Notes

- The codebase uses Rust 2024 edition
- Key dependencies: clap (CLI), nix (system calls), serde (JSON), regex (pattern matching)
- Tests are located in `src/tests/` with comprehensive coverage of filter functionality
- Architecture-specific code is separated into distinct modules for maintainability
- The project follows defensive security principles - all syscall filtering is deny-by-default with explicit allow rules