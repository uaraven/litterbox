# Litterbox

<img src="logo.png" style="width:33%;">

_Litterbox_ is a syscall inspection and sandboxing tool, similar to strace, but with enhanced capabilities. It not only traces system calls but also enforces runtime restrictions by blocking potentially unsafe operations—such as filesystem writes, network access, and process spawning.

## Sandbox

Like `strace`, _Litterbox_ allows tracing the syscalls and blocking them. Syscalls can be filtered based on file paths, even for operations like read or write that don't include them directly. This is achieved by tracking open/close calls to associate file descriptors with paths. Similar tracking is used for sockets and IP addresses.

This functionality allows creation of a sandbox to analyze potentially malicious applications without allowing them to modify the local environment or "call home".

## Syscall Tracing

_Litterbox_ can log syscalls in plain text or JSONL formats, enriching output with contextual data (e.g., file paths for descriptors). Tracing can be selectively enabled:

- Filter syscalls by name, file path, or IP address.
- Exclude startup noise by starting trace only after a specific syscall.
- Specify which syscalls to block and define custom error codes for blocked syscalls.

### Configuration

_Litterbox_ supports two modes of configuration:
 - syscall filters allow to specify syscall names, file paths, IP addresses, etc. to filter on and the actions on
 what to do with the filtered syscalls. Configuration can be defined in a JSON file and reused.
 See [filters doc](docs/filters.md) for more details.
 - Simplified filtering for file, network and process operations. Rest of the syscalls is ignored (but can be logged)

## License

_Litterbox_ is open source and available under the MIT license.
