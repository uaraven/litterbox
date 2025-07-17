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

use crate::filters::{flag_matcher::FlagMatcher, str_matcher::StrMatcher};

#[test]
fn flags_matcher_test() {
    let matcher = FlagMatcher::new(vec!["O_CREAT".to_string(), "O_RDWR".to_string()]);

    assert_eq!(matcher.matches(&"O_RDWR".to_string()), true);
    assert_eq!(matcher.matches(&"O_CREAT".to_string()), true);
    assert_eq!(matcher.matches(&"O_CREAT|O_READ".to_string()), true);
    assert_eq!(matcher.matches(&"O_READ|O_TEMP".to_string()), false);
}
