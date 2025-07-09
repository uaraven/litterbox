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
use crate::filters::matcher::StrMatchOp;

use super::matcher::StrMatcher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressMatcher {
    pub addresses: Vec<String>,
    pub match_op: StrMatchOp,
    pub port: Option<u16>,
}

impl AddressMatcher {
    pub fn new(addresses: Vec<String>, match_op: StrMatchOp, port: Option<u16>) -> Self {
        Self {
            addresses: addresses,
            match_op,
            port,
        }
    }
}

impl StrMatcher for AddressMatcher {
    fn matches(&self, addr: &String) -> bool {
        let (address, port) = match addr.rfind(':') {
            Some(index) => {
                let (address, port_str) = addr.split_at(index);
                let port = port_str.trim_start_matches(':').parse::<u16>().ok();
                (address.to_string(), port.unwrap_or(0))
            }
            None => (addr.clone(), 0),
        };
        if let Some(matcher_port) = self.port {
            // if filter has port defined, only events with the same port will match
            if port != matcher_port {
                return false;
            }
        }
        // if filter doesn't have address defined, any event will match (if port matched)
        if self.addresses.is_empty() {
            return true;
        }
        match self.match_op {
            StrMatchOp::Exact => self.addresses.contains(&address),
            StrMatchOp::Prefix => self.addresses.iter().any(|a| address.starts_with(a)),
            StrMatchOp::Suffix => self.addresses.iter().any(|a| address.ends_with(a)),
            StrMatchOp::Contains => self.addresses.iter().any(|a| address.contains(a)),
        }
    }
}
