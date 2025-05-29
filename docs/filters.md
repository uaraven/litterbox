# Filter syntax

Syscalls can be processed by defining a list of filters. Filters define the condition to match the syscall event and
what to do with the matching events.

```json
{
    "syscall": <int>,
    "args": ???,
    "match_path_created_by_process": true|false,
    "path_matcher": {
        "paths": ["<path1>", "<path2>", ..., "<pathN>"],
        "op": "match|prefix|suffix|contains"
    }
    "flag_matcher": {
        "flags": "<flag>|<flag>|<flag>|<flag>",
    }
    "outcome": {
        "action": "Allow|Block",
        "block_syscall_id": <syscall_id>,
        "tag": "<tag>" | null,
        "log": true|false,
    }
}
```