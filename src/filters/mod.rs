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

pub mod address_matcher;
pub mod context_matcher;
pub mod argument_matcher;
pub mod dto;
pub mod flag_matcher;
pub mod str_matcher;
pub mod path_matcher;
pub mod syscall_filter;
#[cfg(target_arch = "aarch64")]
pub mod syscall_names_aarch64;
#[cfg(target_arch = "x86_64")]
pub mod syscall_names_x86_64;
pub mod utils;
