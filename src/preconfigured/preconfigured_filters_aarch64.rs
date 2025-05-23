use std::{collections::HashMap, vec};

use syscall_numbers::native;

use crate::{
    FilteringLogger,
    syscall_filter::{FilterOutcome, SyscallFilter},
};

pub(crate) fn permissive_filters() -> FilteringLogger {
    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: Default::default(),
        default_filters: vec![SyscallFilter {
            syscall: -1,
            match_path_created_by_process: false,
            args: Default::default(),
            extras: Default::default(),
            outcome: FilterOutcome {
                action: crate::syscall_filter::FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
    }
}

pub(crate) fn restrictive_filters() -> FilteringLogger {
    let filtered_syscalls = vec![
        SyscallFilter::new_stdio_allow(native::SYS_read),
        SyscallFilter::new_stdio_allow(native::SYS_write),
        SyscallFilter::block(native::SYS_write),
        SyscallFilter::block(native::SYS_unlinkat),
        SyscallFilter::block(native::SYS_fchmod),
        SyscallFilter::block(native::SYS_fchmodat),
        SyscallFilter::block(native::SYS_fchmodat2),
        SyscallFilter::block(native::SYS_fchown),
        SyscallFilter::block(native::SYS_fchownat),
    ];

    let filter_map: HashMap<u64, Vec<SyscallFilter>> = filtered_syscalls
        .into_iter()
        .map(|filter| (filter.syscall as u64, vec![filter]))
        .collect();

    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: filter_map,
        default_filters: vec![SyscallFilter {
            syscall: -1,
            match_path_created_by_process: true,
            args: Default::default(),
            extras: Default::default(),
            outcome: FilterOutcome {
                action: crate::syscall_filter::FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
    }
}
