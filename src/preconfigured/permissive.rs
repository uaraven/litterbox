use std::{collections::HashSet, vec};

use crate::{
    FilteringLogger,
    filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
};

// This function returns a permissive filtering logger.
// It allows all syscalls and logs them.
pub(crate) fn permissive_filters() -> FilteringLogger {
    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: Default::default(),
        default_filters: vec![SyscallFilter {
            syscall: HashSet::new(),
            args: Default::default(),
            path_matcher: None,
            flag_matcher: None,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
    }
}
