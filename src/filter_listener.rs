use std::collections::HashMap;

use crate::{
    syscall_common::EXTRA_PATHNAME,
    syscall_event::{SyscallEvent, SyscallEventListener},
    syscall_filter::{FilterAction, SyscallFilter},
    trace_process::TraceProcess,
};

/// This struct describes a syscall that primes the filter. Any syscall before the trigger syscall
/// will be ignored. After the trigger syscall, the filters will be applied to all syscalls.
pub(crate) struct SyscallFilterTrigger {
    syscall_id: i64,
    file_path: Option<String>,
}

impl SyscallFilterTrigger {
    pub fn matches(&self, syscall: &SyscallEvent) -> bool {
        if syscall.id as i64 == self.syscall_id {
            if let Some(ref path) = self.file_path {
                if let Some(extra_path) = syscall.extra_context.get(EXTRA_PATHNAME) {
                    return extra_path == path;
                }
            }
        }
        return false;
    }
}

pub(crate) struct FilteringLogger {
    primed: bool,
    trigger_event: Option<SyscallFilterTrigger>,
    filters: HashMap<u64, Vec<SyscallFilter>>,
}
impl FilteringLogger {
    pub fn new(filters: Vec<SyscallFilter>, trigger_event: Option<SyscallFilterTrigger>) -> Self {
        let mut filter_map: HashMap<u64, Vec<SyscallFilter>> = HashMap::new();
        for filter in filters {
            filter_map
                .entry(filter.syscall as u64)
                .or_insert_with(Vec::new)
                .push(filter);
        }
        Self {
            primed: trigger_event.is_none(),
            trigger_event,
            filters: filter_map,
        }
    }

    pub fn log_event(&self, event: &SyscallEvent) {
        println!("{:?}", event);
    }
}

impl SyscallEventListener for FilteringLogger {
    fn process_event(&mut self, proc: &TraceProcess, event: &SyscallEvent) -> Option<SyscallEvent> {
        if !self.primed {
            if let Some(ref trigger) = self.trigger_event {
                if trigger.matches(event) {
                    self.primed = true;
                } else {
                    return Some(event.clone());
                }
            }
        }
        let filters = self.filters.get(&event.id);
        if let Some(filters) = filters {
            for filter in filters {
                if filter.matches(proc, &event) {
                    // if the filter matches, we review the outcome to figure out what to do
                    let mut event = event.clone();
                    if filter.outcome.log {
                        self.log_event(&event);
                    }
                    if filter.outcome.tag.is_some() {
                        event.label = filter.outcome.tag.clone();
                    }
                    match filter.outcome.action {
                        FilterAction::Block(error) => {
                            return Some(event.block_syscall(Some(error)));
                        }
                        FilterAction::Allow => {}
                    }
                    return Some(event);
                }
            }
        }
        Some(event.clone())
    }
}
