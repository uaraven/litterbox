use crate::filters::matcher::StrMatchOp;

use super::matcher::StrMatcher;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathMatcher {
    pub paths: Vec<String>,
    pub match_op: StrMatchOp,
    pub only_created_by_process: bool,
}

impl PathMatcher {
    pub fn new(paths: Vec<String>, match_op: StrMatchOp, created_by_process: bool) -> Self {
        Self {
            paths,
            match_op,
            only_created_by_process: created_by_process,
        }
    }
}

impl StrMatcher for PathMatcher {
    fn matches(&self, path: &String) -> bool {
        match self.match_op {
            StrMatchOp::Exact => self.paths.contains(&path),
            StrMatchOp::Prefix => self.paths.iter().any(|p| path.starts_with(p)),
            StrMatchOp::Suffix => self.paths.iter().any(|p| path.ends_with(p)),
            StrMatchOp::Contains => self.paths.iter().any(|p| path.contains(p)),
        }
    }
}
