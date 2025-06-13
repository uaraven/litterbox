use crate::filters::{
    address_matcher::AddressMatcher,
    matcher::{StrMatchOp, StrMatcher},
};

#[test]
fn address_matcher_test() {
    let matcher = AddressMatcher::new(vec!["192.168", "172.10"], StrMatchOp::Prefix, Some(8080));

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
    let matcher = AddressMatcher::new(vec!["192.168", "172.10"], StrMatchOp::Prefix, None);

    assert_eq!(matcher.matches(&"192.168.11.0:8080".to_string()), true);
    assert_eq!(matcher.matches(&"192.168.11.0:80".to_string()), true);
    assert_eq!(matcher.matches(&"172.10.1.1:443".to_string()), true);
    assert_eq!(matcher.matches(&"10.10.1.1:443".to_string()), false);
}
