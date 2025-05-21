use std::collections::HashMap;

use crate::{
    syscall_event::{SyscallEvent, SyscallEventListener},
    syscall_filter::{FilterAction, SyscallFilter},
};

pub(crate) struct FilteringLogger {
    filters: HashMap<u64, Vec<SyscallFilter>>,
}
impl FilteringLogger {
    fn log_event(&self, event: &SyscallEvent) {
        todo!()
    }
}

impl SyscallEventListener for FilteringLogger {
    fn process_event(&mut self, event: &SyscallEvent) -> Option<SyscallEvent> {
        let filters = self.filters.get(&event.id);
        if let Some(filters) = filters {
            for filter in filters {
                if filter.matches(event) {
                    match filter.action {
                        FilterAction::Block(error) => {
                            return Some(event.block_syscall(Some(error)));
                        }
                        FilterAction::Process => {
                            self.log_event(event);
                        }
                        FilterAction::Ignore => {
                            // do nothing
                        }
                    }
                    return Some(event.clone());
                }
            }
        }
        Some(event.clone())
    }
}
