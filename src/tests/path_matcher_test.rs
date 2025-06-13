use crate::filters::{
    matcher::{StrMatchOp, StrMatcher},
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
