pub trait StrMatcher {
    fn matches(&self, s: &String) -> bool;
}
