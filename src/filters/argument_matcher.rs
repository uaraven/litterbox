/*
 * Litterbox - A sandboxing and tracing tool
 *
 * Copyright (c) 2025  Oles Voronin
 *
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this
 * program. If not, see <https://www.gnu.org/licenses/>.
 *
 */


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    Equal(u64),
    BitSet(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArgumentMatcher {
    pub arg_index: u8,
    pub matchers: Vec<ArgValue>,
}

impl ArgumentMatcher {
    pub fn new(arg_index: u8, matchers: Vec<ArgValue>) -> Self {
        Self {
            arg_index,
            matchers,
        }
    }

    pub fn matches(&self, value: &u64) -> bool {
        self.matchers.iter().any(|matcher| match matcher {
            ArgValue::Equal(v) => v == value,
            ArgValue::BitSet(v) => (value & v) == *v,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_match() {
        let matcher = ArgumentMatcher::new(0, vec![ArgValue::Equal(42)]);
        assert!(matcher.matches(&42));
        assert!(!matcher.matches(&43));
    }

    #[test]
    fn test_bitset_match() {
        // 0b1010 & 0b1000 == 0b1000
        let matcher = ArgumentMatcher::new(1, vec![ArgValue::BitSet(0b1000)]);
        assert!(matcher.matches(&0b1010));
        assert!(matcher.matches(&0b1000));
        assert!(!matcher.matches(&0b0100));
    }

    #[test]
    fn test_multiple_matchers() {
        let matcher = ArgumentMatcher::new(
            2,
            vec![ArgValue::Equal(10), ArgValue::BitSet(0b11)],
        );
        assert!(matcher.matches(&10)); // Equal
        assert!(matcher.matches(&0b111)); // BitSet
        assert!(!matcher.matches(&8));
    }

    #[test]
    fn test_no_matchers() {
        let matcher = ArgumentMatcher::new(3, vec![]);
        assert!(!matcher.matches(&0));
        assert!(!matcher.matches(&123));
    }

    #[test]
    fn test_bitset_zero() {
        let matcher = ArgumentMatcher::new(4, vec![ArgValue::BitSet(0)]);
        assert!(matcher.matches(&0));
        assert!(matcher.matches(&123)); // 123 & 0 == 0
    }

    #[test]
    fn test_equal_and_bitset_overlap() {
        let matcher = ArgumentMatcher::new(
            5,
            vec![ArgValue::Equal(7), ArgValue::BitSet(0b100)],
        );
        assert!(matcher.matches(&7)); // Equal
        assert!(matcher.matches(&0b1100)); // BitSet
        assert!(!matcher.matches(&2));
    }
}
