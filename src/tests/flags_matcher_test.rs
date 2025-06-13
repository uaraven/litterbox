use crate::filters::{flag_matcher::FlagMatcher, matcher::StrMatcher};

#[test]
fn flags_matcher_test() {
    let matcher = FlagMatcher::new(vec!["O_CREAT".to_string(), "O_RDWR".to_string()]);

    assert_eq!(matcher.matches(&"O_RDWR".to_string()), true);
    assert_eq!(matcher.matches(&"O_CREAT".to_string()), true);
    assert_eq!(matcher.matches(&"O_CREAT|O_READ".to_string()), true);
    assert_eq!(matcher.matches(&"O_READ|O_TEMP".to_string()), false);
}
