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
        if port != 0 && self.port.is_some() && port != self.port.unwrap() {
            return false;
        }
        match self.match_op {
            StrMatchOp::Exact => self.addresses.contains(&address),
            StrMatchOp::Prefix => self.addresses.iter().any(|a| address.starts_with(a)),
            StrMatchOp::Suffix => self.addresses.iter().any(|a| address.ends_with(a)),
            StrMatchOp::Contains => self.addresses.iter().any(|a| address.contains(a)),
        }
    }
}
