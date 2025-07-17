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

use crate::filters::{
    str_matcher::{StrMatchOp, StrMatcher},
    path_matcher::PathMatcher,
};

#[test]
fn path_matcher_prefix_test() {
    let matcher = PathMatcher::new(
        vec!["/lib".to_string(), "/tmp".to_string()],
        StrMatchOp::Prefix,
        true,
    );

    assert_eq!(matcher.matches(&"/lib/libc.so".to_string()), true);
    assert_eq!(matcher.matches(&"/etc/passwd".to_string()), false);
    assert_eq!(matcher.matches(&"/tmp/test".to_string()), true);
    assert_eq!(matcher.matches(&"/home/root/tmp/test".to_string()), false);
}

#[test]
fn path_matcher_contains_test() {
    let matcher = PathMatcher::new(
        vec!["/lib".to_string(), "/tmp".to_string()],
        StrMatchOp::Contains,
        true,
    );

    assert_eq!(matcher.matches(&"/lib/libc.so".to_string()), true);
    assert_eq!(matcher.matches(&"/usr/lib/passwd".to_string()), true);
    assert_eq!(matcher.matches(&"/etc/passwd".to_string()), false);
    assert_eq!(matcher.matches(&"/tmp/test".to_string()), true);
    assert_eq!(matcher.matches(&"/home/root/tmp/test".to_string()), true);
}
