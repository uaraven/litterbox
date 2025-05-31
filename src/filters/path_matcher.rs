use super::matcher::StrMatcher;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PathMatchOp {
    Exact,
    Prefix,
    Suffix,
    Contains,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathMatcher {
    pub paths: Vec<String>,
    pub match_op: PathMatchOp,
}

impl PathMatcher {
    pub fn new(paths: Vec<String>, match_op: PathMatchOp) -> Self {
        Self { paths, match_op }
    }
}

impl StrMatcher for PathMatcher {
    fn matches(&self, path: &String) -> bool {
        match self.match_op {
            PathMatchOp::Exact => self.paths.contains(&path),
            PathMatchOp::Prefix => self.paths.iter().any(|p| path.starts_with(p)),
            PathMatchOp::Suffix => self.paths.iter().any(|p| path.ends_with(p)),
            PathMatchOp::Contains => self.paths.iter().any(|p| path.contains(p)),
        }
    }
}
