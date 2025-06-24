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

use crate::filters::matcher::StrMatchOp;

use super::matcher::StrMatcher;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathMatcher {
    pub paths: Vec<String>,
    pub match_op: StrMatchOp,
    pub only_created_by_process: bool,
}

impl PathMatcher {
    pub fn new(paths: Vec<String>, match_op: StrMatchOp, created_by_process: bool) -> Self {
        Self {
            paths,
            match_op,
            only_created_by_process: created_by_process,
        }
    }
}

impl StrMatcher for PathMatcher {
    fn matches(&self, path: &String) -> bool {
        match self.match_op {
            StrMatchOp::Exact => self.paths.contains(&path),
            StrMatchOp::Prefix => self.paths.iter().any(|p| path.starts_with(p)),
            StrMatchOp::Suffix => self.paths.iter().any(|p| path.ends_with(p)),
            StrMatchOp::Contains => self.paths.iter().any(|p| path.contains(p)),
        }
    }
}
