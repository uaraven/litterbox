use syscall_numbers::native;

use crate::{
    FilteringLogger,
    filters::syscall_filter::{FilterOutcome, SyscallFilter},
};

fn get_allowed_paths() -> Vec<String> {
    let home = std::env::var("HOME")
        .ok()
        .map(|path| std::path::PathBuf::from(&path))
        .or_else(|| std::env::current_dir().ok())
        .map(|path| path.canonicalize().unwrap())
        .unwrap()
        .to_string_lossy()
        .to_string();
    let allowed_paths = vec![
        "/tmp/".to_string(),
        "/var/tmp/".to_string(),
        home.clone(),
        home,
    ];
    allowed_paths
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn default_filters() -> FilteringLogger {
    use std::collections::HashSet;

    use crate::{
        filters::{syscall_filter::FilterAction, utils::group_filters_by_syscall},
        simple_logger::simple_logger,
    };

    let allowed_path_list = get_allowed_paths();

    let filtered_syscalls = vec![
        SyscallFilter::stdio_allow(native::SYS_write),
        SyscallFilter::allow(&[native::SYS_write], &allowed_path_list),
        SyscallFilter::with_paths_and_flags(
            native::SYS_openat,
            true,
            &allowed_path_list,
            crate::filters::path_matcher::PathMatchOp::Prefix,
            &vec![String::from("O_CREAT")],
        ),
        SyscallFilter::block(&[
            native::SYS_write,
            native::SYS_writev,
            native::SYS_pwritev,
            native::SYS_pwritev2,
            native::SYS_pwrite64,
            native::SYS_unlinkat,
            native::SYS_mknodat,
            native::SYS_mkdirat,
            native::SYS_chroot,
            native::SYS_linkat,
            native::SYS_symlinkat,
            native::SYS_setxattr,
            native::SYS_fsetxattr,
            native::SYS_removexattr,
            native::SYS_fremovexattr,
            native::SYS_sendfile,
            native::SYS_io_setup,
            native::SYS_fchmod,
            native::SYS_fchmodat,
            native::SYS_fchmodat2,
            native::SYS_fchown,
            native::SYS_fchownat,
            native::SYS_execve,
            native::SYS_execveat,
            native::SYS_connect,
            native::SYS_listen,
            native::SYS_recvfrom,
            native::SYS_recvmmsg,
            native::SYS_recvmsg,
            native::SYS_sendto,
            native::SYS_sendmsg,
            native::SYS_sendmmsg,
        ]),
    ];

    let filter_map = group_filters_by_syscall(filtered_syscalls);

    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: filter_map,
        default_filters: vec![SyscallFilter {
            syscall: HashSet::new(),
            args: Default::default(),
            path_matcher: None,
            flag_matcher: None,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
        logger: Some(simple_logger),
    }
}

/// This function returns a restrictive filtering logger.
/// It blocks all syscalls except for a few allowed ones.
/// It also logs all syscalls.
#[cfg(target_arch = "x86_64")]
pub(crate) fn default_filters() -> FilteringLogger {
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
