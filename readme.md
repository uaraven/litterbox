# Litterbox

<img src="logo.png" style="width:33%;">

_Litterbox_ is a sandboxing and syscall tracing tool designed for analyzing potentially malicious applications in a controlled environment.

It allows you to run an application while blocking unsafe system calls — such as file modifications, network activity, and process spawning — and provides detailed syscall logs with enhanced context.

<span style="color:red; font-variant:small-caps;"><b>WARNING</b>: The raison d'être of this project is me learning Rust. While the program does what it says on the lid (mostly), it has not been thouroughly tested yet and should not be relied upon.</span>

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

#### Sandbox 

In the sandbox mode _Litterbox_ intercepts predefined set of syscalls and logs them. Some of the syscalls are blocked. The only syscalls that are intercepted are:

 - read and write to stdin, stdout and stderr - logged
 - filesystem reads - logged
 - filesystem writes - logged and blocked (except for /tmp folder)
 - listen on network socket - logged and blocked
 - connect to other host - logged and blocked
 - execute another process - logged and blocked
 - shutdown - logged and blocked

```shell
$ litterbox --sandbox [--allow-write <folder-prefix>...] [--allow-spawn <program-name>...] [--allow-connect <ip-address-prefix>...] -- program-name args...
```

This will run the binary `program-name` with CLI parameters `args...` in a sandbox environment. By default the program is not
allowed to write anything to the storage (except in /tmp folder), it is not allowed to connected to any host or listen for
incoming connections and it cannot start any other programs. These restrictions can be relaxed a bit.

`--allow-write` enables writing to a directory. One may add multiple directories using multiple `--allow-write` parameters. All subdirectories will also be writable.

`--allow-connect` enables connecting to a given IP address(es). IP addresses are matched as simple string prefixes, e.g. `--allow-connect 192.168.` will allow connection to all IP addresses starting with `192.168`.

`--allow-spawn` allows `program-name` to start other programs. Arguments to `--allow-spawn` are matched as suffixes, e.g. 
`--allow-spawn bash` will match /bin/bash, /usr/bin/bash or /home/user/any/directory/bash.

#### Custom filter mode

```shell
$ litterbox --filter --filter-file <filter-file> -- program-name args...
```

In this mode _Litterbox_ only does what the filters in the `filter-file` tells it to do. By default it doesn't intercept any syscalls, doesn't block anything or logs anything.

`filter-file` containing the filters must be provided. See [filter documentation](docs/filters.md) for more information on using filters.

#### Common options

- `--output <log-file>` - writes _Litterbox_ output into the `log-file` instead of stdout
- `--log-format text|jsonl` - configures the format of the output. JSONL format is better for machine parsing of the results
- `--verbose` - produce more verbose output



## License

_Litterbox_ is open source and available under the MIT license.
