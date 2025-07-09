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

use std::collections::{HashMap, HashSet};

use crate::filters::syscall_filter::SyscallFilter;

#[cfg(target_arch = "aarch64")]
use crate::filters::syscall_names_aarch64 as syscall_names;
#[cfg(target_arch = "x86_64")]
use crate::filters::syscall_names_x86_64 as syscall_names;

pub(crate) fn group_filters_by_syscall(
    filtered_syscalls: Vec<SyscallFilter>,
) -> HashMap<u64, Vec<SyscallFilter>> {
    let filter_map: HashMap<u64, Vec<SyscallFilter>> =
        filtered_syscalls
            .into_iter()
            .fold(HashMap::new(), |mut acc, filter| {
                for syscall in filter.matcher.syscall.iter() {
                    acc.entry(*syscall as u64)
                        .or_insert_with(Vec::new)
                        .push(filter.clone());
                }
                acc
            });
    filter_map
}

pub(crate) fn syscall_id_by_name(name: &str) -> Option<u64> {
    syscall_names::SYS_CALL_NAME
        .iter()
        .position(|&n| n == name)
        .map(|idx| (idx + syscall_names::SYS_CALL_BASE_INDEX) as u64)
}

pub(crate) fn syscall_ids_by_names(names: Vec<&str>) -> HashSet<i64> {
    names
        .into_iter()
        .filter_map(|name| syscall_id_by_name(name))
        .map(|id| id as i64)
        .collect()
}
