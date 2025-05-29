use std::collections::HashMap;

use syscall_numbers::native;

use crate::{
    FilteringLogger,
    syscall_filter::{FilterOutcome, SyscallFilter},
};

/// This function returns a restrictive filtering logger.
/// It blocks all syscalls that could modify the filesystem, initiate network connection or execute new processes.
/// It also logs all syscalls.
// #[cfg(target_arch = "aarch64")]
// pub(crate) fn restrictive_filters() -> FilteringLogger {
//     use crate::{syscall_common::EXTRA_FLAGS, syscall_filter::ExtraParameter};

//     let filtered_syscalls = vec![
//         SyscallFilter::new_stdio_allow(native::SYS_write),
//         SyscallFilter::with_extras(
//             native::SYS_openat,
//             true,
//             &[&ExtraParameter {
//                 name: EXTRA_FLAGS,
//                 value: ".*O_CREAT.*".to_string(),
//             }],
//         ),
//         SyscallFilter::block(native::SYS_write),
//         SyscallFilter::block(native::SYS_writev),
//         SyscallFilter::block(native::SYS_pwritev),
//         SyscallFilter::block(native::SYS_pwritev2),
//         SyscallFilter::block(native::SYS_pwrite64),
//         SyscallFilter::block(native::SYS_unlinkat),
//         SyscallFilter::block(native::SYS_mknodat),
//         SyscallFilter::block(native::SYS_mkdirat),
//         SyscallFilter::block(native::SYS_chroot),
//         SyscallFilter::block(native::SYS_linkat),
//         SyscallFilter::block(native::SYS_symlinkat),
//         SyscallFilter::block(native::SYS_setxattr),
//         SyscallFilter::block(native::SYS_fsetxattr),
//         SyscallFilter::block(native::SYS_removexattr),
//         SyscallFilter::block(native::SYS_fremovexattr),
//         SyscallFilter::block(native::SYS_sendfile),
//         SyscallFilter::block(native::SYS_io_setup),
//         SyscallFilter::block(native::SYS_fchmod),
//         SyscallFilter::block(native::SYS_fchmodat),
//         SyscallFilter::block(native::SYS_fchmodat2),
//         SyscallFilter::block(native::SYS_fchown),
//         SyscallFilter::block(native::SYS_fchownat),
//         SyscallFilter::block(native::SYS_execve),
//         SyscallFilter::block(native::SYS_execveat),
//         SyscallFilter::block(native::SYS_connect),
//         SyscallFilter::block(native::SYS_listen),
//         SyscallFilter::block(native::SYS_recvfrom),
//         SyscallFilter::block(native::SYS_recvmmsg),
//         SyscallFilter::block(native::SYS_recvmsg),
//         SyscallFilter::block(native::SYS_sendto),
//         SyscallFilter::block(native::SYS_sendmsg),
//         SyscallFilter::block(native::SYS_sendmmsg),
//     ];

//     let filter_map: HashMap<u64, Vec<SyscallFilter>> = filtered_syscalls
//         .into_iter()
//         .map(|filter| (filter.syscall as u64, vec![filter]))
//         .collect();

//     FilteringLogger {
//         primed: true,
//         trigger_event: None,
//         filters: filter_map,
//         default_filters: vec![SyscallFilter {
//             syscall: -1,
//             match_path_created_by_process: true,
//             args: Default::default(),
//             extras: Default::default(),
//             outcome: FilterOutcome {
//                 action: crate::syscall_filter::FilterAction::Allow,
//                 log: true,
//                 tag: None,
//             },
//         }],
//     }
// }

/// This function returns a restrictive filtering logger.
/// It blocks all syscalls except for a few allowed ones.
/// It also logs all syscalls.
#[cfg(target_arch = "x86_64")]
pub(crate) fn restrictive_filters() -> FilteringLogger {
    let filtered_syscalls = vec![
        SyscallFilter::new_stdio_allow(x86_64::SYS_write),
        SyscallFilter::block(x86_64::SYS_write),
        SyscallFilter::block(x86_64::SYS_writev),
        SyscallFilter::block(x86_64::SYS_pwrite),
        SyscallFilter::block(x86_64::SYS_pwritev),
        SyscallFilter::block(x86_64::SYS_pwritev2),
        SyscallFilter::block(x86_64::SYS_pwrite64),
        SyscallFilter::block(x86_64::SYS_unlink),
        SyscallFilter::block(x86_64::SYS_unlinkat),
        SyscallFilter::block(x86_64::SYS_rmdir),
        SyscallFilter::block(x86_64::SYS_mknod),
        SyscallFilter::block(x86_64::SYS_mknodat),
        SyscallFilter::block(x86_64::SYS_mkdir),
        SyscallFilter::block(x86_64::SYS_mkdirat),
        SyscallFilter::block(x86_64::SYS_chroot),
        SyscallFilter::block(x86_64::SYS_link),
        SyscallFilter::block(x86_64::SYS_linkat),
        SyscallFilter::block(x86_64::SYS_symlinkat),
        SyscallFilter::block(x86_64::SYS_setxattr),
        SyscallFilter::block(x86_64::SYS_fsetxattr),
        SyscallFilter::block(x86_64::SYS_removexattr),
        SyscallFilter::block(x86_64::SYS_fremovexattr),
        SyscallFilter::block(x86_64::SYS_sendfile),
        SyscallFilter::block(x86_64::SYS_io_setup),
        SyscallFilter::block(x86_64::SYS_chmod),
        SyscallFilter::block(x86_64::SYS_fchmod),
        SyscallFilter::block(x86_64::SYS_fchmodat),
        SyscallFilter::block(x86_64::SYS_fchmodat2),
        SyscallFilter::block(x86_64::SYS_chown),
        SyscallFilter::block(x86_64::SYS_fchown),
        SyscallFilter::block(x86_64::SYS_fchownat),
        SyscallFilter::block(x86_64::SYS_execve),
        SyscallFilter::block(x86_64::SYS_execveat),
        SyscallFilter::block(x86_64::SYS_connect),
        SyscallFilter::block(x86_64::SYS_listen),
        SyscallFilter::block(x86_64::SYS_recvfrom),
        SyscallFilter::block(x86_64::SYS_recvmmsg),
        SyscallFilter::block(x86_64::SYS_recvmsg),
        SyscallFilter::block(x86_64::SYS_sendto),
        SyscallFilter::block(x86_64::SYS_sendmsg),
        SyscallFilter::block(x86_64::SYS_sendmmsg),
    ];

    let filter_map: HashMap<u64, Vec<SyscallFilter>> = filtered_syscalls
        .into_iter()
        .map(|filter| (filter.syscall as u64, vec![filter]))
        .collect();

    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: filter_map,
        default_filters: vec![SyscallFilter {
            syscall: -1,
            match_path_created_by_process: true,
            args: Default::default(),
            extras: Default::default(),
            outcome: FilterOutcome {
                action: crate::syscall_filter::FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
    }
}
