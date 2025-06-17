# Filter syntax

Syscalls can be processed by defining a list of filters. Filters define the condition to match the syscall event and
what to do with the matching events.

```json
{
    "matcher": {
      "syscall_names": ["name1", "name2", ..., "nameN"],
      "args": {"<arg0>": [value1, value2, ..., valueN], ...},
      "paths": {
        "paths": ["<path1>", "<path2>", ..., "<pathN>"],
        "compare_op": "match|prefix|suffix|contains",
        "match_path_created_by_process": true|false,
      },
      "addresses": {
        "addresses": ["<addr1>", ..., "<addrN>"],
        "compare_op": "match|prefix|suffix|contains",
        "port": <port>,
      }
      "flags": "<flag>|<flag>|<flag>|<flag>",
    },
    "outcome": {
        "action": "Allow|Block",
        "block_syscall_error": <error_code>,
        "tag": "<tag>" | null,
        "log": true|false,
    }
}
```

## JSON fields

 - "matcher" - a matcher object containing conditions to match syscall events
    - `syscall_names` - a list of syscall names, such as "openat" or "sendmsg". If the name is not defined
 for the current architecture, it is silently ignored
    - `args` - a map of argument index to possible values. Each syscall can have up to 6 arguments. If there are multiple values for a syscall argument, it's enough for any of them to match
    - `paths` - matches events by file paths. Contains following subfields:
      - `paths` - list of paths to match. 
      - `compare_op` - the operation with which to compare paths. One of:
        - `match` - the operation path must match one of the paths/addresses on the list
        - `prefix` - the operation path starts with one of the paths/addresses on the list
        - `suffix` - the operation path ends with one of the paths/addresses on the list
        - `contains` - the operation path contains with one of the paths/addresses on the list
      - `match_path_created_by_process` - if the path matches (see below), then record it as a match only if this path was created by the process. This allows to allow writes (and renames and deletes) of the files created by the process, for example, temporary files.
    - `addresses` - matches events by addresses. Used with network-related syscalls.
      - `addresses` - list of addresses to match. This could be partial addresses, like "192.168."
      - `compare_op` - the operation with which to compare addresses. Same values as for paths.
      - `port` - port to match. Port 0 matches any port, or just omit this field
    - `flags` - list of flags to match. Flags are strings matching one of the flags used in sycall. For example for `open` syscall this can be `O_RDONLY` or `O_CREAT`
 - `outcome` - what to do if the filter matches
   - `action` - what to do with the syscall. One of the values: 'Allow' or 'Block'
   - `block_syscall_error` error code to return from blocked syscall.
   - `tag` - if not null, tag the event with this string
   - `log` - if true will log the syscall
   

You must specify only one of `paths` or `addresses` matchers. If both are specified, the `addresses` matcher will be ignored.