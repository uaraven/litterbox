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
use crate::filters::address_matcher::AddressMatcher;
use crate::filters::context_matcher::ContextMatcher;
use crate::filters::str_matcher::StrMatchOp;
use crate::filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher};
use crate::filters::utils::syscall_ids_by_names;
use std::collections::HashSet;

pub(crate) fn create_network_filter(allowed_addresses: Vec<&str>) -> Vec<SyscallFilter> {
    let network_syscalls = vec![
        // read operations
        "listen", "connect",
    ];
    let network_syscall_ids: HashSet<i64> = syscall_ids_by_names(network_syscalls);

    // by default, we allow connections to DNS services
    let mut filters = vec![SyscallFilter {
        matcher: SyscallMatcher {
            syscall: syscall_ids_by_names(vec!["connect"]),
            args: vec![],
            context_matcher: Some(ContextMatcher::AddressMatcher(AddressMatcher::new(
                vec![],
                StrMatchOp::Prefix,
                Some(53),
            ))),
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            tag: Some("network".to_string()),
            log: true,
        },
    }];
    if !allowed_addresses.is_empty() {
        filters.push(SyscallFilter {
            matcher: SyscallMatcher {
                syscall: network_syscall_ids.clone(),
                args: vec![],
                context_matcher: Some(ContextMatcher::AddressMatcher(AddressMatcher::new(
                    allowed_addresses
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect(),
                    StrMatchOp::Prefix,
                    None,
                ))),
                flag_matcher: None,
            },
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                tag: Some("network".to_string()),
                log: true,
            },
        });
    }
    filters.push(SyscallFilter {
        matcher: SyscallMatcher {
            syscall: network_syscall_ids,
            args: vec![],
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Block(-1) ,
            tag: Some("network".to_string()),
            log: true,
        },
    });
    filters
}
