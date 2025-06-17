# Litterbox

<img src="logo.png" style="width:33%;">

_Litterbox_ is a sandboxing and syscall tracing tool designed for analyzing potentially malicious applications in a controlled environment.

It allows you to run an application while blocking unsafe system calls — such as file modifications, network activity, and process spawning — and provides detailed syscall logs with enhanced context.

## Sandbox

Like `strace`, _Litterbox_ allows tracing the syscalls and blocking them. Syscalls can be filtered based on file paths or IP addresses, even for syscalls like `read`, `write` or `sendmsg`, that don't include this information. This is achieved by tracking open/close calls to associate file descriptors with paths. Similar tracking is used for sockets and IP addresses.

This functionality allows creation of a sandbox to analyze potentially malicious applications without allowing them to modify the local environment or establish network connections.

## Syscall Tracing

Litterbox provides flexible syscall logging, with support for:

 - Output in plain text or [JSONL](https://jsonlines.org/) formats
 - Filtering by syscall name, file path, or IP address
 - Defining custom error codes for blocked syscalls
 - Starting trace after a specific syscall (to skip initialization noise)
 - Tagging syscall events for easier post-processing

### Configuration

_Litterbox_ supports two modes of configuration:
 - syscall filters allow to specify syscall names, file paths, IP addresses, etc. to filter on and the actions on
 what to do with the filtered syscalls. Configuration can be defined in a JSON file and reused.
 See [filters doc](docs/filters.md) for more details.
 - Simplified filtering for file, network and process operations. Rest of the syscalls is ignored (but can be logged)


### Running

TBD

## License

_Litterbox_ is open source and available under the MIT license.
