use crate::{
    fd_utils::is_fdcwd,
    regs::Regs,
    syscall_common::{EXTRA_CWD, EXTRA_DIRFD},
    syscall_event::ExtraData,
    trace_process::TraceProcess,
};

pub(crate) fn add_dirfd_extra(proc: &mut TraceProcess, dirfd: i64, extra: &mut ExtraData) {
    if is_fdcwd(dirfd as i32) {
        extra.insert(EXTRA_CWD, proc.get_cwd());
    } else if let Some(fd_data) = proc.get_fd(dirfd as i64) {
        extra.insert(EXTRA_DIRFD, fd_data.value.clone());
    }
}

pub(crate) fn add_fd_filepath(
    proc: &mut TraceProcess,
    regs: &Regs,
    is_entry: bool,
    extras: &mut ExtraData,
) -> u64 {
    let fd = match is_entry {
        true => regs.regs[0],
        false => proc
            .get_last_syscall(regs.syscall_id)
            .map(|event| event.regs.regs[0])
            .unwrap_or(regs.regs[0]),
    };
    if let Some(fd_data) = proc.get_fd(fd as i64) {
        extras.insert(fd_data.name, fd_data.value.clone());
    };
    fd
}
