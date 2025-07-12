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

#[cfg(test)]
use crate::filters::{
    context_matcher::ContextMatcher, dto::SyscallFilterDto, syscall_filter::FilterAction,
};
#[cfg(test)]
use serde_json::json;

#[cfg(test)]
fn base_json() -> serde_json::Value {
    json!({
        "matcher": {
            "syscall_names": ["openat"],
            "args": [
                { "arg_index": 0, "values": [{"value":1, "op":"eq"}, {"value":2, "op":"eq"}] },
                { "arg_index": 1, "values": [{"value":3, "op":"eq"}] }
            ],
            "paths": {
                "paths": ["/tmp/file", "/var/log"],
                "compare_op": "exact",
                "match_created_by_process": true,
            },
            "flags": ["O_RDONLY", "O_CREAT"],
        },
        "outcome": {
            "tag": "test",
            "log": true,
            "action": "allow",
            "block_syscall_error": null
        }
    })
}

#[test]
fn test_from_json_success() {
    let json_str = base_json().to_string();
    let dto = SyscallFilterDto::from_json(json_str);
    assert!(dto.is_ok());
    let dto = dto.unwrap();
    assert_eq!(*dto.matcher.syscall_names.first().unwrap(), "openat");
    let path_matcher = dto.matcher.paths.unwrap();
    assert_eq!(path_matcher.paths.len(), 2);
    assert_eq!(dto.matcher.flags, vec!["O_RDONLY", "O_CREAT"]);
    assert!(path_matcher.match_created_by_process);
    assert_eq!(dto.outcome.tag, "test");
    assert!(dto.outcome.log);
    assert_eq!(dto.outcome.action, "allow");
}

#[test]
fn test_parse_outcome_action_allow() {
    let json = base_json();
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let action = dto.parse_outcome_action().unwrap();
    assert!(matches!(action, FilterAction::Allow));
}

#[test]
fn test_parse_outcome_action_block_with_replace_id() {
    let mut json = base_json();
    json["outcome"]["action"] = json!("block");
    json["outcome"]["block_syscall_error"] = json!(42);
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let action = dto.parse_outcome_action().unwrap();
    assert!(matches!(action, FilterAction::Block(42)));
}

#[test]
fn test_parse_outcome_action_block_missing_replace_id() {
    let mut json = base_json();
    json["outcome"]["action"] = json!("block");
    json["outcome"]["block_syscall_error"] = serde_json::Value::Null;
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let err = dto.parse_outcome_action().unwrap_err();
    assert!(
        err.message
            .contains("Block action requires a syscall error code")
    );
}

#[test]
fn test_parse_outcome_action_invalid() {
    let mut json = base_json();
    json["outcome"]["action"] = json!("invalid");
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let err = dto.parse_outcome_action().unwrap_err();
    assert!(err.message.contains("Invalid outcome action"));
}

#[test]
fn test_to_syscall_filter_success() {
    let json = base_json();
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter();
    assert!(filter.is_ok());
    let filter = filter.unwrap();
    assert_eq!(filter.matcher.syscall.len(), 1);
    assert!(filter.matcher.context_matcher.is_some());
    assert!(filter.matcher.flag_matcher.is_some());
    if let Some(ContextMatcher::PathMatcher(path_matcher)) = filter.matcher.context_matcher {
        assert!(path_matcher.only_created_by_process);
    } else {
        panic!("Expected PathMatcher in context_matcher");
    }
    assert_eq!(filter.outcome.tag, Some("test".to_string()));
    assert!(filter.outcome.log);
}

#[test]
fn test_to_syscall_filter_empty_paths_and_flags() {
    let mut json = base_json();
    json["matcher"]["paths"] = json!(null);
    json["matcher"]["flags"] = json!([]);
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.matcher.context_matcher.is_none());
    assert!(filter.matcher.flag_matcher.is_none());
}

#[test]
fn test_to_syscall_filter_empty_tag() {
    let mut json = base_json();
    json["outcome"]["tag"] = json!("");
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert_eq!(filter.outcome.tag, None);
}

#[test]
fn test_to_syscall_filter_addresses() {
    let mut json = base_json();
    json["matcher"]["paths"] = json!(null);
    json["matcher"]["flags"] = json!([]);
    json["matcher"]["addresses"] =
        json!({"addresses":["192.168.10.1", "172.10."], "port": 53, "compare_op": "exact"});
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.matcher.flag_matcher.is_none());
    if let Some(ContextMatcher::AddressMatcher(addr_matcher)) = filter.matcher.context_matcher {
        assert_eq!(addr_matcher.addresses.len(), 2);
        assert_eq!(addr_matcher.port, Some(53));
    } else {
        panic!("Expected AddressMatcher in context_matcher");
    }
}
