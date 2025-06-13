# Litterbox

<img src="logo.png" style="width:33%;">

_Litterbox_ is a tool to inspect the usage of syscalls, similar to standard Linux utility `strace`.
In addition to tracing the syscalls, _litterbox_ also allows application sandboxing, by blocking "unsafe"
syscalls such as writes to filesystems, network access and process spawning. _Litterbox_ will also provide
a report on which files the app has tried to access, which network addresses (hosts and IPs) it tried to connect to
and which processes it tried to start.

### Sandbox

By default _litterbox_ is very restrictive. It doesn't allow reading or writing from and to files. It prevents creation of new and deletion of existing files and folders. Only file descriptors 0,1,2 are allowed to be read and written to.
Litterbox blocks all outgoing socket connections and attempts to start a server.
Litterbox blocks spawning of new processes (it doesn't block `clone` or `fork`, but it does block `execve`, etc.)

_Litterbox_ can block syscalls based on file path, even the syscalls that do not include the file path, like `read` or
`write`. _Litterbox_ does this by keeping track of all `open` and `close` calls and associating file paths with file
descriptors. It can do the same for sockets, keeping track of IP addresses associated with the socket descriptor.

### Syscall tracing

_Litterbox_ can log the syscalls in text and JSONL formats. It will include additional information for relevant syscalls,
such as file path associated with a file descriptor.
User can choose which syscalls to ignore and only log the information about the syscalls that present interest.

_Litterbox_ can ignore all syscalls until the specific one that triggers the start of tracing. This allows to ignore
the application startup phase, with all the libraries being loaded and littering the logs with unnecessary information.
We all know that the libc.so will be loaded, right?

User can choose which syscalls to log, based on syscall names, file paths or IP addresses used. User can also decide to
block some of the syscalls and choose which error code will be returned.

### Configuration

_Litterbox_ supports two modes of configuration:
 - syscall filters allow to specify syscall names, file paths, IP addresses, etc. to filter on and the actions on
 what to do with the filtered syscalls. Configuration can be defined in a JSON file and reused.
 See [filters doc](docs/filters.md) for more details.
 - Simplified filtering for file, network and process operations. Rest of the syscalls is ignored (but can be logged)

## License

_Litterbox_ is open source and available under the MIT license.