#[cfg(test)]
use crate::filters::{
    dto::SyscallFilterDto, dto::parse_compare_op, matcher::StrMatchOp, syscall_filter::FilterAction,
};
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use syscall_numbers::native;

#[cfg(test)]
fn base_dto_json() -> serde_json::Value {
    json!({
        "matcher":{
            "syscall_names": ["openat", "read"],
            "args": { "0": [1, 2], "1": [3] },
            "paths": {
                "paths": ["/tmp/file", "/var/log"],
                "compare_op": "exact",
                "match_created_by_process": true,
            },
            "flags": ["O_RDONLY"],
        },
        "outcome": {
            "tag": "test_tag",
            "log": true,
            "action": "allow",
            "block_syscall_error": null
        }
    })
}

#[test]
fn test_parse_path_op_valid() {
    // let mut dto = SyscallFilterDto::from_json(base_dto_json().to_string()).unwrap();
    assert_eq!(parse_compare_op("prefix").unwrap(), StrMatchOp::Prefix);
    assert_eq!(parse_compare_op("exact").unwrap(), StrMatchOp::Exact);
    assert_eq!(parse_compare_op("suffix").unwrap(), StrMatchOp::Suffix);
    assert_eq!(parse_compare_op("contains").unwrap(), StrMatchOp::Contains);
    assert!(parse_compare_op("invalid").is_err());
}

#[test]
fn test_parse_outcome_action_allow() {
    let dto = SyscallFilterDto::from_json(base_dto_json().to_string()).unwrap();
    assert!(matches!(
        dto.parse_outcome_action().unwrap(),
        FilterAction::Allow
    ));
}

#[test]
fn test_parse_outcome_action_block_with_error() {
    let mut json = base_dto_json();
    json["outcome"]["action"] = json!("block");
    json["outcome"]["block_syscall_error"] = json!(13);
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    match dto.parse_outcome_action().unwrap() {
        FilterAction::Block(code) => assert_eq!(code, 13),
        _ => panic!("Expected Block variant"),
    }
}

#[test]
fn test_parse_outcome_action_block_missing_error() {
    let mut json = base_dto_json();
    json["outcome"]["action"] = json!("block");
    json["outcome"]["block_syscall_error"] = serde_json::Value::Null;
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    assert!(dto.parse_outcome_action().is_err());
}

#[test]
fn test_parse_outcome_action_invalid() {
    let mut json = base_dto_json();
    json["outcome"]["action"] = json!("invalid_action");
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    assert!(dto.parse_outcome_action().is_err());
}

#[test]
fn test_to_syscall_filter_success() {
    let dto = SyscallFilterDto::from_json(base_dto_json().to_string()).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.matcher.syscall.contains(&(native::SYS_openat as i64)));
    assert!(filter.matcher.syscall.contains(&(native::SYS_read as i64)));
    assert!(filter.matcher.args.get(&0).unwrap().contains(&1));
    assert!(filter.matcher.args.get(&0).unwrap().contains(&2));
    assert!(filter.matcher.args.get(&1).unwrap().contains(&3));
    assert!(filter.matcher.context_matcher.is_some());
    assert!(filter.matcher.flag_matcher.is_some());
    assert_eq!(filter.outcome.tag, Some("test_tag".to_string()));
    assert!(filter.outcome.log);
}

#[test]
fn test_to_syscall_filter_empty_paths_and_flags() {
    let mut json = base_dto_json();
    json["matcher"]["paths"] = json!(null);
    json["matcher"]["flags"] = json!([]);
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.matcher.context_matcher.is_none());
    assert!(filter.matcher.flag_matcher.is_none());
}

#[test]
fn test_to_syscall_filter_empty_tag() {
    let mut json = base_dto_json();
    json["outcome"]["tag"] = json!("");
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert_eq!(filter.outcome.tag, None);
}

#[test]
fn test_to_syscall_filter_invalid_path_op() {
    let mut json = base_dto_json();
    json["matcher"]["paths"]["compare_op"] = json!("invalid");
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    assert!(dto.to_syscall_filter().is_err());
}

#[test]
fn test_to_syscall_filter_invalid_action() {
    let mut json = base_dto_json();
    json["outcome"]["action"] = json!("invalid");
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    assert!(dto.to_syscall_filter().is_err());
}

#[test]
fn test_to_syscall_filter_invalid_syscall_name() {
    let mut json = base_dto_json();
    json["matcher"]["syscall_names"] = vec![json!("openat15")].into();
    let dto = SyscallFilterDto::from_json(json.to_string()).unwrap();
    let filter = dto.to_syscall_filter().unwrap();
    assert!(filter.matcher.syscall.is_empty());
    assert!(filter.matcher.args.get(&0).unwrap().contains(&1));
    assert!(filter.matcher.args.get(&0).unwrap().contains(&2));
    assert!(filter.matcher.args.get(&1).unwrap().contains(&3));
    assert!(filter.matcher.context_matcher.is_some());
    assert!(filter.matcher.flag_matcher.is_some());
    assert_eq!(filter.outcome.tag, Some("test_tag".to_string()));
    assert!(filter.outcome.log);
}
