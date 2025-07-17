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
    address_matcher::AddressMatcher,
    str_matcher::{StrMatchOp, StrMatcher},
};

#[test]
fn address_matcher_test() {
    let matcher = AddressMatcher::new(
        vec!["192.168".to_string(), "172.10".to_string()],
        StrMatchOp::Prefix,
        Some(8080),
    );

    assert_eq!(matcher.matches(&"192.168.11.0:8080".to_string()), true);
    assert_eq!(matcher.matches(&"192.168.11.0:80".to_string()), false);
    assert_eq!(
        matcher.matches(&"10.10.192.168.11.0:8080".to_string()),
        false
    );
    assert_eq!(matcher.matches(&"172.10.1.1:8080".to_string()), true);
}

#[test]
fn address_matcher_port_test() {
    let matcher = AddressMatcher::new(
        vec!["192.168".to_string(), "172.10".to_string()],
        StrMatchOp::Prefix,
        None,
    );

    assert_eq!(matcher.matches(&"192.168.11.0:8080".to_string()), true);
    assert_eq!(matcher.matches(&"192.168.11.0:80".to_string()), true);
    assert_eq!(matcher.matches(&"172.10.1.1:443".to_string()), true);
    assert_eq!(matcher.matches(&"10.10.1.1:443".to_string()), false);
}
