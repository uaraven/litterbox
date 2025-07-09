use std::collections::{HashMap, HashSet};

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
use crate::filter_listener::FilteringLogger;
use crate::filter_loader::FilterError;
use crate::filters::syscall_filter::{FilterAction, FilterOutcome, SyscallFilter, SyscallMatcher};
use crate::loggers::syscall_logger::SyscallLogger;
use crate::sandbox::sandbox_network::create_network_filter;
use crate::sandbox::sandbox_read_filter::create_reader_filter;
use crate::sandbox::sandbox_write_filter::create_write_filter;

fn default_filter() -> SyscallFilter {
    SyscallFilter {
        matcher: SyscallMatcher {
            syscall: HashSet::default(),
            args: HashMap::default(),
            context_matcher: None,
            flag_matcher: None,
        },
        outcome: FilterOutcome {
            action: FilterAction::Allow,
            tag: None,
            log: false,
        },
    }
}

pub(crate) fn create_sandbox_filters(
    logger: Box<dyn SyscallLogger>,
    allow_write: Vec<&str>,
    allow_connect: Vec<&str>,
    allow_spawn: Vec<&str>,
) -> Result<FilteringLogger, FilterError> {
    let cwd = std::env::current_dir().unwrap();
    let mut writable_paths = vec![cwd.to_str().unwrap(), "/tmp", "/var/tmp"];
    writable_paths.extend(allow_write);
    let mut connectable_addresses = vec!["127.0.0.1", "::1"];
    connectable_addresses.extend(allow_connect);

    let mut filters = create_write_filter();
    filters.push(create_reader_filter());
    filters.extend(create_network_filter(connectable_addresses));
    filters.push(default_filter());

    Ok(FilteringLogger::new(filters, None, Some(logger)))
}
