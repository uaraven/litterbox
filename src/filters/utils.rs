use std::collections::HashMap;

use crate::filters::syscall_filter::SyscallFilter;

#[cfg(target_arch = "aarch64")]
use crate::filters::syscall_names_aarch64 as syscall_names;
#[cfg(target_arch = "x86_64")]
use crate::filters::syscall_names_x86_64 as syscall_names;

pub(crate) fn group_filters_by_syscall(
    filtered_syscalls: Vec<SyscallFilter>,
) -> HashMap<u64, Vec<SyscallFilter>> {
    let filter_map: HashMap<u64, Vec<SyscallFilter>> =
        filtered_syscalls
            .into_iter()
            .fold(HashMap::new(), |mut acc, filter| {
                for syscall in filter.syscall.iter() {
                    acc.entry(*syscall as u64)
                        .or_insert_with(Vec::new)
                        .push(filter.clone());
                }
                acc
            });
    filter_map
}

pub(crate) fn syscall_id_by_name(name: &str) -> Option<u64> {
    syscall_names::SYS_CALL_NAME
        .iter()
        .position(|&n| n == name)
        .map(|idx| (idx + syscall_names::SYS_CALL_BASE_INDEX) as u64)
}
