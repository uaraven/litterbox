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

use std::collections::HashSet;

use crate::filters::path_matcher::PathMatcher;
use crate::filters::{
    context_matcher::ContextMatcher,
    str_matcher::StrMatchOp,
    syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher},
    utils::syscall_ids_by_names,
};

pub(crate) fn create_process_filter(allowed_binaries: Vec<&str>) -> Vec<SyscallFilter> {
    let exec_syscalls = vec!["execve", "execveat"];
    let exec_syscall_ids: HashSet<i64> = syscall_ids_by_names(exec_syscalls);

    let mut result = vec![];
    let log_outcome = FilterOutcome {
        action: FilterAction::Allow,
        tag: Some("spawn".to_string()),
        log: true,
    };

    result.push(
        SyscallFilter{
            matcher: SyscallMatcher {
                syscall: syscall_ids_by_names(vec!["fork", "vfork"]),
                args: vec![],
                context_matcher: None,
                flag_matcher: None
            },
            outcome: log_outcome.clone(),
        }
    );

    if !allowed_binaries.is_empty() {
        result.push(
            SyscallFilter {
                matcher: SyscallMatcher {
                    syscall: exec_syscall_ids.clone(),
                    args: vec![],
                    context_matcher: Some(ContextMatcher::PathMatcher(PathMatcher::new(
                        allowed_binaries
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect(),
                        StrMatchOp::Suffix,
                        false,
                    ))),
                    flag_matcher: None,
                },
                outcome: log_outcome,
            }
        );
    }
    result.push(
        SyscallFilter {
            matcher: SyscallMatcher {
                syscall: exec_syscall_ids,
                args: vec![],
                context_matcher: None,
                flag_matcher: None,
            },
            outcome: FilterOutcome {
                action: FilterAction::Block(-1),
                tag: Some("spawn".to_string()),
                log: true,
            },
        }
    );
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter_listener::FilteringLogger;
    use crate::filters::utils::syscall_id_by_name;
    use crate::regs::Regs;
    use crate::syscall_common::EXTRA_PATHNAME;
    use crate::syscall_event::{ExtraData, SyscallStopType};
    use crate::syscall_event::{SyscallEvent, SyscallEventListener};
    use crate::trace_process::TraceProcess;
    use std::collections::HashMap;

    fn create_test_syscall_event(
        syscall_name: &str,
        extra: &ExtraData,
        regs: &Regs,
    ) -> SyscallEvent {
        SyscallEvent {
            id: regs.syscall_id,
            name: syscall_name.to_string(),
            set_syscall_id: |_, _, _| Ok(()),
            pid: 1000,
            arguments: Default::default(),
            regs: regs.clone(),
            return_value: 0,
            stop_type: SyscallStopType::Enter,
            extra_context: extra.clone(),
            blocked: false,
            label: None,
        }
    }

    fn test_event_filter(
        filters: Vec<SyscallFilter>,
        proc: &TraceProcess,
        event: &SyscallEvent,
        expected_blocked: bool,
    ) {
        let mut filtering_logger = FilteringLogger::new(filters, None, None);
        let result = filtering_logger.process_event(&proc, &event);

        assert!(result.is_some());
        assert_eq!(result.unwrap().blocked, expected_blocked);
    }

    #[test]
    fn test_create_process_filter_with_binaries_allowed() {
        let filters = create_process_filter(vec!["/usr/bin/bash", "/bin/sh"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execve syscall to allowed binary should be allowed
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/bash".to_string());

        let mut regs = Regs::default();
        if let Some(execve_id) = syscall_id_by_name("execve") {
            regs.syscall_id = execve_id;
        }

        let event = create_test_syscall_event("execve", &extra, &regs);

        test_event_filter(filters, &proc, &event, false);
    }

    #[test]
    fn test_create_process_filter_with_binaries_blocked() {
        let filters = create_process_filter(vec!["/usr/bin/bash", "/bin/sh"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execve syscall to disallowed binary should be blocked
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/evil".to_string());

        let mut regs = Regs::default();
        if let Some(execve_id) = syscall_id_by_name("execve") {
            regs.syscall_id = execve_id;
        }

        let event = create_test_syscall_event("execve", &extra, &regs);

        test_event_filter(filters, &proc, &event, true);
    }

    #[test]
    fn test_create_process_filter_with_binaries_suffix_match() {
        let filters = create_process_filter(vec!["bash", "sh"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execve syscall to path ending with allowed suffix should be allowed
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/bash".to_string());

        let mut regs = Regs::default();
        if let Some(execve_id) = syscall_id_by_name("execve") {
            regs.syscall_id = execve_id;
        }

        let event = create_test_syscall_event("execve", &extra, &regs);

        test_event_filter(filters, &proc, &event, false);
    }

    #[test]
    fn test_create_process_filter_execveat_allowed() {
        let filters = create_process_filter(vec!["/usr/bin/bash"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execveat syscall to allowed binary should be allowed
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/bash".to_string());

        let mut regs = Regs::default();
        if let Some(execveat_id) = syscall_id_by_name("execveat") {
            regs.syscall_id = execveat_id;
        }

        let event = create_test_syscall_event("execveat", &extra, &regs);

        test_event_filter(filters, &proc, &event, false);
    }

    #[test]
    fn test_create_process_filter_execveat_blocked() {
        let filters = create_process_filter(vec!["/usr/bin/bash"]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execveat syscall to disallowed binary should be blocked
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/evil".to_string());

        let mut regs = Regs::default();
        if let Some(execveat_id) = syscall_id_by_name("execveat") {
            regs.syscall_id = execveat_id;
        }

        let event = create_test_syscall_event("execveat", &extra, &regs);

        test_event_filter(filters, &proc, &event, true);
    }

    #[test]
    fn test_create_process_filter_empty_binaries_blocks_all() {
        let filters = create_process_filter(vec![]);
        let proc = TraceProcess::new(nix::unistd::Pid::from_raw(1000));

        // Test execve syscall with empty allowed binaries should be blocked
        let mut extra = HashMap::new();
        extra.insert(EXTRA_PATHNAME, "/usr/bin/bash".to_string());

        let mut regs = Regs::default();
        if let Some(execve_id) = syscall_id_by_name("execve") {
            regs.syscall_id = execve_id;
        }

        let event = create_test_syscall_event("execve", &extra, &regs);

        test_event_filter(filters, &proc, &event, true);
    }

    #[test]
    fn test_process_filter_outcome_structure() {
        let filters = create_process_filter(vec!["/bin/sh"]);
        
        // Test that filters have correct structure
        assert!(!filters.is_empty());
        
        // Find the allow filter (should be first if allowed_binaries is not empty)
        let allow_filter = &filters[0];
        match allow_filter.outcome.action {
            FilterAction::Allow => {},
            _ => panic!("Expected Allow action for first filter"),
        }
        assert_eq!(allow_filter.outcome.tag, Some("spawn".to_string()));
        assert!(allow_filter.outcome.log);
        
        // Find the block filter (should be last)
        let block_filter = filters.last().unwrap();
        match block_filter.outcome.action {
            FilterAction::Block(error_code) => assert_eq!(error_code, -1),
            _ => panic!("Expected Block action for last filter"),
        }
        assert_eq!(block_filter.outcome.tag, Some("spawn".to_string()));
        assert!(block_filter.outcome.log);
    }
}
