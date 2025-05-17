pub struct TriggerEvent {
    pub syscall_name: String,
    pub file_path: Option<String>,
}

pub struct Config {
    start_after: TriggerEvent,
    allow_reads_from: Vec<String>,
    allow_writes_to: Vec<String>,
    allow_deletes_from: Vec<String>,

    allow_delete_created: bool,
    allow_cwd: bool,

    allow_connect_to: Vec<String>,
    allow_listen: bool,
    allow_exec_from: Vec<String>,

    trace_syscalls: Vec<String>,
}
