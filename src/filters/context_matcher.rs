use crate::filters::{address_matcher::AddressMatcher, path_matcher::PathMatcher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextMatcher {
    PathMatcher(PathMatcher),
    AddressMatcher(AddressMatcher),
}
