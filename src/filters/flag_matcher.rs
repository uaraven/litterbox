use super::matcher::StrMatcher;

pub struct FlagMatcher {
    flags: Vec<String>,
}

impl FlagMatcher {
    pub fn new(flags: Vec<String>) -> Self {
        Self { flags }
    }
}

impl StrMatcher for FlagMatcher {
    fn matches(&self, flags: &String) -> bool {
        self.flags.iter().any(|f| flags.contains(f))
    }
}
