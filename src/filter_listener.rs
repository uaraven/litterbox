/*
 * Litterbox - A sandboxing and tracing tool
 *
 * Copyright (c) 2025  Oles Voronin
 *
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this
 * program. If not, see <https://www.gnu.org/licenses/>.
 *
 */
use std::collections::HashMap;

use crate::filters::syscall_filter::SyscallMatcher;
use crate::{
    TextLogger,
    filters::{
        syscall_filter::{FilterAction, SyscallFilter},
        utils::group_filters_by_syscall,
    },
    loggers::syscall_logger::SyscallLogger,
    preconfigured::default::default_filters,
    syscall_event::{SyscallEvent, SyscallEventListener},
    trace_process::TraceProcess,
};

pub(crate) struct FilteringLogger {
    pub primed: bool,
    pub trigger_event: Option<SyscallMatcher>,
    pub filters: HashMap<u64, Vec<SyscallFilter>>,
    pub default_filters: Vec<SyscallFilter>,
    pub logger: Option<Box<dyn SyscallLogger>>,
}

impl Default for FilteringLogger {
    fn default() -> Self {
        default_filters(Box::new(TextLogger {}))
    }
}

impl FilteringLogger {
    pub fn new(
        filters: Vec<SyscallFilter>,
        trigger_event: Option<SyscallMatcher>,
        logger: Option<Box<dyn SyscallLogger>>,
    ) -> Self {
        let mut filter_map: HashMap<u64, Vec<SyscallFilter>> = HashMap::new();
        let mut defaults: Vec<SyscallFilter> = Vec::new();
        for filter in filters {
            if filter.matcher.syscall.is_empty() {
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
            logger.log_event(event);
        }
    }

    fn handle_filter(
        &self,
        proc: &TraceProcess,
        event: &SyscallEvent,
        filter: &SyscallFilter,
    ) -> Option<SyscallEvent> {
        if filter.matcher.matches(proc, &event) {
            // if the filter matches, we review the outcome to figure out what to do
            let mut event = event.clone();
            if filter.outcome.tag.is_some() {
                event.label = filter.outcome.tag.clone();
            }
            let new_event = match filter.outcome.action {
                FilterAction::Block(error) => event.block_syscall(Some(error)),
                FilterAction::Allow => event.clone(),
            };
            if filter.outcome.log {
                self.log_event(&new_event);
            }

            return Some(new_event);
        }
        None
    }
}

impl SyscallEventListener for FilteringLogger {
    fn process_event(&mut self, proc: &TraceProcess, event: &SyscallEvent) -> Option<SyscallEvent> {
        if !self.primed {
            if let Some(ref trigger) = self.trigger_event {
                if trigger.matches(proc, event) {
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
