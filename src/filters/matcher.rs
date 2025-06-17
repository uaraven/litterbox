pub trait StrMatcher {
    fn matches(&self, s: &String) -> bool;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StrMatchOp {
    Exact,
    Prefix,
    Suffix,
    Contains,
}
