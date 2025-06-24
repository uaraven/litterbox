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
use std::{collections::HashSet, vec};

use crate::filters::syscall_filter::SyscallMatcher;
use crate::{
    FilteringLogger,
    filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
    loggers::syscall_logger::SyscallLogger,
};

// This function returns a permissive filtering logger.
// It allows all syscalls and logs them.
pub(crate) fn permissive_filters(logger: Box<dyn SyscallLogger>) -> FilteringLogger {
    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: Default::default(),
        default_filters: vec![SyscallFilter {
            matcher: SyscallMatcher {
                syscall: HashSet::new(),
                args: Default::default(),
                context_matcher: None,
                flag_matcher: None,
            },
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
        logger: Some(logger),
    }
}
