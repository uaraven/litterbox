pub struct TriggerEvent {
    pub syscall_name: String,
    pub file_path: Option<String>,
}

pub struct Config {
    pub start_after: TriggerEvent,
    pub allow_reads_from: Vec<String>,
    pub allow_writes_to: Vec<String>,
    pub allow_deletes_from: Vec<String>,

    pub allow_delete_created: bool,
    pub allow_cwd: bool,

    pub allow_connect_to: Vec<String>,
    pub allow_listen: bool,
    pub allow_exec_from: Vec<String>,

    pub trace_syscalls: Vec<String>,
}
