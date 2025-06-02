use std::collections::HashMap;

use crate::{
    filters::syscall_filter::{FilterAction, SyscallFilter},
    filters::utils::group_filters_by_syscall,
    preconfigured::default::default_filters,
    syscall_common::EXTRA_PATHNAME,
    syscall_event::{SyscallEvent, SyscallEventListener},
    syscall_logger::SyscallLogger,
    trace_process::TraceProcess,
};

/// This struct describes a syscall that primes the filter. Any syscall before the trigger syscall
/// will be ignored. After the trigger syscall, the filters will be applied to all syscalls.
pub(crate) struct SyscallFilterTrigger {
    pub syscall_id: i64,
    pub file_path: Option<String>,
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
    pub primed: bool,
    pub trigger_event: Option<SyscallFilterTrigger>,
    pub filters: HashMap<u64, Vec<SyscallFilter>>,
    pub default_filters: Vec<SyscallFilter>,
    pub logger: Option<SyscallLogger>,
}

impl FilteringLogger {
    pub fn default() -> Self {
        default_filters()
    }

    #[cfg(test)]
    pub fn new(
        filters: Vec<SyscallFilter>,
        trigger_event: Option<SyscallFilterTrigger>,
        logger: Option<SyscallLogger>,
    ) -> Self {
        let mut filter_map: HashMap<u64, Vec<SyscallFilter>> = HashMap::new();
        let mut defaults: Vec<SyscallFilter> = Vec::new();
        for filter in filters {
            if filter.syscall.is_empty() {
                defaults.push(filter);
                continue;
            } else {
                filter_map.extend(group_filters_by_syscall(vec![filter]));
            }
        }
        Self {
            primed: trigger_event.is_none(),
            trigger_event,
            filters: filter_map,
            default_filters: defaults,
            logger: logger,
        }
    }

    pub fn log_event(&self, event: &SyscallEvent) {
        if let Some(ref logger) = self.logger {
            logger(event);
        }
    }

    fn handle_filter(
        &self,
        proc: &TraceProcess,
        event: &SyscallEvent,
        filter: &SyscallFilter,
    ) -> Option<SyscallEvent> {
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
        None
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
        // first check if we have a filter for this syscall
        let filters = self.filters.get(&event.id);
        if let Some(m_filters) = filters {
            for filter in m_filters {
                if let Some(value) = self.handle_filter(proc, event, &filter) {
                    return Some(value);
                }
            }
        }
        // if we haven't found a filter for the syscall number, we check the default filters
        for d_filter in &self.default_filters {
            if let Some(value) = self.handle_filter(proc, event, d_filter) {
                return Some(value);
            }
        }
        Some(event.clone())
    }
}
