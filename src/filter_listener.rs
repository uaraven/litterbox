use std::collections::HashMap;

#[cfg(target_arch = "aarch64")]
use syscall_numbers::aarch64;

#[cfg(target_arch = "x86_64")]
use syscall_numbers::x86_64;

use crate::{
    filters::syscall_filter::{FilterAction, SyscallFilter},
    syscall_common::EXTRA_PATHNAME,
    syscall_event::{SyscallEvent, SyscallEventListener},
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
    pub(crate) primed: bool,
    pub(crate) trigger_event: Option<SyscallFilterTrigger>,
    pub(crate) filters: HashMap<u64, Vec<SyscallFilter>>,
    pub(crate) default_filters: Vec<SyscallFilter>,
}

#[cfg(target_arch = "x86_64")]
fn blocked_syscalls() -> Vec<SyscallFilter> {
    vec![
        SyscallFilter::block(x86_64::SYS_execve),
        SyscallFilter::block(x86_64::SYS_execveat),
        SyscallFilter::block(x86_64::SYS_write),
        SyscallFilter::block(x86_64::SYS_writev),
        SyscallFilter::block(x86_64::SYS_pwritev),
        SyscallFilter::block(x86_64::SYS_pwritev2),
        SyscallFilter::block(x86_64::SYS_pwrite64),
        SyscallFilter::block(x86_64::SYS_unlink),
        SyscallFilter::block(x86_64::SYS_unlinkat),
        SyscallFilter::block(x86_64::SYS_rmdir),
        SyscallFilter::block(x86_64::SYS_chown),
        SyscallFilter::block(x86_64::SYS_fchown),
        SyscallFilter::block(x86_64::SYS_lchown),
        SyscallFilter::block(x86_64::SYS_chmod),
        SyscallFilter::block(x86_64::SYS_fchmod),
        SyscallFilter::block(x86_64::SYS_fchmodat),
        SyscallFilter::block(x86_64::SYS_fchmodat2),
        SyscallFilter::block(x86_64::SYS_connect),
        SyscallFilter::block(x86_64::SYS_listen),
    ]
}

#[cfg(target_arch = "x86_64")]
fn allowed_syscalls() -> Vec<SyscallFilter> {
    vec![
        SyscallFilter::new_stdio_allow(x86_64::SYS_read),
        SyscallFilter::new_stdio_allow(x86_64::SYS_readv),
        SyscallFilter::new_stdio_allow(x86_64::SYS_preadv),
        SyscallFilter::new_stdio_allow(x86_64::SYS_preadv2),
        SyscallFilter::new_stdio_allow(x86_64::SYS_pread64),
        SyscallFilter::new_stdio_allow(x86_64::SYS_write),
        SyscallFilter::new_stdio_allow(x86_64::SYS_writev),
        SyscallFilter::new_stdio_allow(x86_64::SYS_pwritev),
        SyscallFilter::new_stdio_allow(x86_64::SYS_pwritev2),
        SyscallFilter::new_stdio_allow(x86_64::SYS_pwrite64),
    ]
}

#[cfg(target_arch = "aarch64")]
fn blocked_syscalls() -> Vec<SyscallFilter> {
    vec![
        SyscallFilter::block(aarch64::SYS_execve),
        SyscallFilter::block(aarch64::SYS_execveat),
        SyscallFilter::block(aarch64::SYS_write),
        SyscallFilter::block(aarch64::SYS_writev),
        SyscallFilter::block(aarch64::SYS_pwritev),
        SyscallFilter::block(aarch64::SYS_pwritev2),
        SyscallFilter::block(aarch64::SYS_pwrite64),
        SyscallFilter::block(aarch64::SYS_unlinkat),
        SyscallFilter::block(aarch64::SYS_fchown),
        SyscallFilter::block(aarch64::SYS_fchmod),
        SyscallFilter::block(aarch64::SYS_fchmodat),
        SyscallFilter::block(aarch64::SYS_fchmodat2),
        SyscallFilter::block(aarch64::SYS_connect),
        SyscallFilter::block(aarch64::SYS_listen),
    ]
}

#[cfg(target_arch = "aarch64")]
fn allowed_syscalls() -> Vec<SyscallFilter> {
    vec![
        SyscallFilter::stdio_allow(aarch64::SYS_recvfrom),
        SyscallFilter::stdio_allow(aarch64::SYS_read),
        SyscallFilter::stdio_allow(aarch64::SYS_readv),
        SyscallFilter::stdio_allow(aarch64::SYS_preadv),
        SyscallFilter::stdio_allow(aarch64::SYS_preadv2),
        SyscallFilter::stdio_allow(aarch64::SYS_pread64),
        SyscallFilter::stdio_allow(aarch64::SYS_sendto),
        SyscallFilter::stdio_allow(aarch64::SYS_write),
        SyscallFilter::stdio_allow(aarch64::SYS_writev),
        SyscallFilter::stdio_allow(aarch64::SYS_pwritev),
        SyscallFilter::stdio_allow(aarch64::SYS_pwritev2),
        SyscallFilter::stdio_allow(aarch64::SYS_pwrite64),
    ]
}

impl FilteringLogger {
    pub fn default() -> Self {
        let mut filters = Vec::new();
        filters.extend(allowed_syscalls());
        filters.extend(blocked_syscalls());
        Self {
            primed: true,
            trigger_event: None,
            filters: HashMap::new(),
            default_filters: filters,
        }
    }

    #[cfg(test)]
    pub fn new(filters: Vec<SyscallFilter>, trigger_event: Option<SyscallFilterTrigger>) -> Self {
        let mut filter_map: HashMap<u64, Vec<SyscallFilter>> = HashMap::new();
        let mut defaults: Vec<SyscallFilter> = Vec::new();
        for filter in filters {
            if filter.syscall.is_empty() {
                defaults.push(filter);
                continue;
            } else {
                filter_map.extend(crate::filters::utils::group_filters_by_syscall(vec![
                    filter,
                ]));
            }
        }
        Self {
            primed: trigger_event.is_none(),
            trigger_event,
            filters: filter_map,
            default_filters: defaults,
        }
    }

    pub fn log_event(&self, event: &SyscallEvent) {
        println!("{:?}", event);
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
