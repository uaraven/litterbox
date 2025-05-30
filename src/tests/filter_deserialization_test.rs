use std::ops::Deref;

use serde_json::json;

use crate::filters::{
    dto::SyscallFilterDto, path_matcher::PathMatchOp, syscall_filter::FilterAction,
};

fn base_json() -> serde_json::Value {
    json!({
        "syscall_id": [1],
        "args": { "0": [1, 2], "1": [3] },
        "paths": ["/tmp/file", "/var/log"],
        "path_op": "exact",
        "flags": ["O_RDONLY", "O_CREAT"],
        "match_path_created_by_process": true,
        "outcome": {
            "tag": "test",
            "log": true,
            "action": "allow",
            "replace_syscall_id": null
        }
    })
}

#[test]
fn test_from_json_success() {
    let json_str = base_json().to_string();
    let dto = SyscallFilterDto::from_json(json_str);
    assert!(dto.is_ok());
    let dto = dto.unwrap();
    assert_eq!(*dto.syscall_id.first().unwrap(), 1);
    assert_eq!(dto.paths.len(), 2);
    assert_eq!(dto.flags, vec!["O_RDONLY", "O_CREAT"]);
    assert!(dto.match_path_created_by_process);
    assert_eq!(dto.outcome.tag, "test");
    assert!(dto.outcome.log);
    assert_eq!(dto.outcome.action, "allow");
}

#[test]
fn test_parse_path_op_variants() {
    let mut json = base_json();
    for (op, expected) in [
        ("exact", PathMatchOp::Exact),
        ("prefix", PathMatchOp::Prefix),
        ("suffix", PathMatchOp::Suffix),
        ("contains", PathMatchOp::Contains),
    ] {
        json["path_op"] = json!(op);
        let dto: SyscallFilterDto = serde_json::from_value(json.clone()).unwrap();
        let parsed = dto.parse_path_op().unwrap();
        assert_eq!(parsed, expected);
    }
}

#[test]
fn test_parse_path_op_invalid() {
    let mut json = base_json();
    json["path_op"] = json!("invalid");
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let err = dto.parse_path_op().unwrap_err();
    assert!(err.message.contains("Invalid path match operation"));
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
    json["outcome"]["replace_syscall_id"] = json!(42);
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let action = dto.parse_outcome_action().unwrap();
    assert!(matches!(action, FilterAction::Block(42)));
}

#[test]
fn test_parse_outcome_action_block_missing_replace_id() {
    let mut json = base_json();
    json["outcome"]["action"] = json!("block");
    json["outcome"]["replace_syscall_id"] = serde_json::Value::Null;
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let err = dto.parse_outcome_action().unwrap_err();
    assert!(
        err.message
            .contains("Block action requires a replace syscall ID")
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
    assert_eq!(filter.syscall.len(), 1);
    assert!(filter.path_matcher.is_some());
    assert!(filter.flag_matcher.is_some());
    assert!(filter.match_path_created_by_process);
    assert_eq!(filter.outcome.tag, Some("test".to_string()));
    assert!(filter.outcome.log);
}

#[test]
fn test_to_syscall_filter_empty_paths_and_flags() {
    let mut json = base_json();
    json["paths"] = json!([]);
    json["flags"] = json!([]);
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.path_matcher.is_none());
    assert!(filter.flag_matcher.is_none());
}

#[test]
fn test_to_syscall_filter_empty_tag() {
    let mut json = base_json();
    json["outcome"]["tag"] = json!("");
    let dto: SyscallFilterDto = serde_json::from_value(json).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert_eq!(filter.outcome.tag, None);
}
