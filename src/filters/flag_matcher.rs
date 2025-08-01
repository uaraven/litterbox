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

use super::str_matcher::StrMatcher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagMatcher {
    flags: Vec<String>,
}

impl FlagMatcher {
    pub fn new(flags: Vec<String>) -> Self {
        Self { flags }
    }
}

impl StrMatcher for FlagMatcher {
    fn matches(&self, flags: &String) -> bool {
        self.flags.iter().any(|f| flags.contains(f))
    }
}
