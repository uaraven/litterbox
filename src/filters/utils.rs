use std::collections::HashMap;

use crate::filters::syscall_filter::SyscallFilter;

pub(crate) fn group_filters_by_syscall(
    filtered_syscalls: Vec<SyscallFilter>,
) -> HashMap<u64, Vec<SyscallFilter>> {
    let filter_map: HashMap<u64, Vec<SyscallFilter>> =
        filtered_syscalls
            .into_iter()
            .fold(HashMap::new(), |mut acc, filter| {
                acc.entry(filter.syscall as u64)
                    .or_insert_with(Vec::new)
                    .push(filter);
                acc
            });
    filter_map
}
