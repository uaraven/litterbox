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

#[cfg(test)]
use std::{collections::HashMap, vec};

#[cfg(test)]
use crate::{
    filters::syscall_filter::FilterAction,
    regs::Regs,
    sandbox::sandbox_network::create_network_filter,
    syscall_common::EXTRA_ADDR,
    syscall_event::{SyscallEvent, SyscallEventListener, SyscallStopType},
    trace_process::TraceProcess,
    FilteringLogger,
};
#[cfg(test)]
use nix::{libc::user_regs_struct, unistd::Pid};
#[cfg(test)]
use syscall_numbers::native;

#[cfg(test)]
fn fake_syscall_id(_pid: Pid, _regs: user_regs_struct, _new_id: u64) -> Result<(), nix::Error> {
    Ok(())
}

#[cfg(test)]
fn make_network_event(syscall_name: &str, address: Option<&str>) -> SyscallEvent {
    let mut extra_context: HashMap<&'static str, String> = HashMap::new();
    if let Some(addr) = address {
        extra_context.insert(EXTRA_ADDR, addr.to_string());
    }

    let syscall_id = match syscall_name {
        "listen" => native::SYS_listen as u64,
        "connect" => native::SYS_connect as u64,
        _ => 0,
    };

    SyscallEvent {
        id: syscall_id,
        name: syscall_name.to_string(),
        pid: 1000,
        set_syscall_id: fake_syscall_id,
        arguments: Default::default(),
        regs: Regs::default(),
        return_value: 0,
        stop_type: SyscallStopType::Enter,
        extra_context,
        blocked: false,
        label: None,
    }
}

#[test]
fn test_create_network_filter_empty_allowed_addresses() {
    let filters = create_network_filter(vec![]);

    // Should have 2 filters: DNS allow + block all
    assert_eq!(filters.len(), 2);

    // First filter should allow DNS connections (port 53)
    let dns_filter = &filters[0];
    assert!(matches!(dns_filter.outcome.action, FilterAction::Allow));
    assert_eq!(dns_filter.outcome.tag, Some("network".to_string()));
    assert_eq!(dns_filter.outcome.log, true);

    // Second filter should block all other network syscalls
    let block_filter = &filters[1];
    assert!(matches!(
        block_filter.outcome.action,
        FilterAction::Block(_)
    ));
    assert_eq!(block_filter.outcome.tag, Some("network".to_string()));
    assert_eq!(block_filter.outcome.log, true);
}

#[test]
fn test_create_network_filter_with_allowed_addresses() {
    let allowed_addresses = vec!["192.168", "10.0"];
    let filters = create_network_filter(allowed_addresses);

    // Should have 3 filters: DNS allow + allowed addresses + block all
    assert_eq!(filters.len(), 3);

    // First filter should allow DNS connections
    let dns_filter = &filters[0];
    assert!(matches!(dns_filter.outcome.action, FilterAction::Allow));

    // Second filter should allow specified addresses
    let allow_filter = &filters[1];
    assert!(matches!(allow_filter.outcome.action, FilterAction::Allow));
    assert_eq!(allow_filter.outcome.tag, Some("network".to_string()));

    // Third filter should block all other network syscalls
    let block_filter = &filters[2];
    assert!(matches!(
        block_filter.outcome.action,
        FilterAction::Block(_)
    ));
}

#[test]
fn test_network_filter_blocks_listen_by_default() {
    let filters = create_network_filter(vec![]);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("listen", Some("0.0.0.0:8080"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_blocks_connect_by_default() {
    let filters = create_network_filter(vec![]);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("connect", Some("192.168.1.100:443"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_allows_dns_connect() {
    let filters = create_network_filter(vec![]);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("connect", Some("8.8.8.8:53"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(!result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_allows_connect_to_allowed_address() {
    let allowed_addresses = vec!["192.168"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("connect", Some("192.168.1.100:443"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(!result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_allows_listen_to_allowed_address() {
    let allowed_addresses = vec!["127.0.0.1"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("listen", Some("127.0.0.1:8080"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(!result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_blocks_connect_to_disallowed_address() {
    let allowed_addresses = vec!["192.168.1.0/24"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("connect", Some("10.0.0.1:443"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_blocks_listen_to_disallowed_address() {
    let allowed_addresses = vec!["127.0.0.1"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    let event = make_network_event("listen", Some("0.0.0.0:8080"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_multiple_allowed_addresses() {
    let allowed_addresses = vec!["192.168.1.0", "10.0.0.1", "127.0.0.1"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    // Test connect to first allowed range
    let event1 = make_network_event("connect", Some("192.168.1.50:443"));
    let result1 = logger.process_event(&proc, &event1).unwrap();
    assert!(result1.blocked);

    // Test connect to second allowed address
    let event2 = make_network_event("connect", Some("10.0.0.1:22"));
    let result2 = logger.process_event(&proc, &event2).unwrap();
    assert!(!result2.blocked);

    // Test connect to third allowed address
    let event3 = make_network_event("connect", Some("127.0.0.1:3000"));
    let result3 = logger.process_event(&proc, &event3).unwrap();
    assert!(!result3.blocked);

    // Test connect to disallowed address
    let event4 = make_network_event("connect", Some("172.16.0.1:443"));
    let result4 = logger.process_event(&proc, &event4).unwrap();
    assert!(result4.blocked);
}

#[test]
fn test_network_filter_dns_takes_precedence() {
    let allowed_addresses = vec!["192.168.1.0/24"];
    let filters = create_network_filter(allowed_addresses);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    // DNS should be allowed even if the IP is not in allowed addresses
    let event = make_network_event("connect", Some("1.1.1.1:53"));
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(!result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}

#[test]
fn test_network_filter_no_address_context_blocked() {
    let filters = create_network_filter(vec![]);
    let mut logger = FilteringLogger::new(filters, None, None);
    let proc = TraceProcess::new(Pid::from_raw(1000));

    // Event without address context should be blocked
    let event = make_network_event("connect", None);
    let result = logger.process_event(&proc, &event).unwrap();

    assert!(result.blocked);
    assert_eq!(result.label, Some("network".to_string()));
}
