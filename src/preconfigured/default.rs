use syscall_numbers::native;

use crate::filters::matcher::StrMatchOp;
use crate::{
    FilteringLogger,
    filters::syscall_filter::{FilterOutcome, SyscallFilter},
    loggers::syscall_logger::SyscallLogger,
};
use std::collections::HashSet;

use crate::filters::{syscall_filter::FilterAction, utils::group_filters_by_syscall};
use crate::filters::syscall_filter::SyscallMatcher;

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
/// default_filters returns a default filtering logger.
/// It allows syscalls that are necessary for basic operations
/// and blocks potentially harmful syscalls.
/// Amongst ther
#[cfg(target_arch = "aarch64")]
pub(crate) fn default_filters(logger: Box<dyn SyscallLogger>) -> FilteringLogger {
    let allowed_path_list = get_allowed_paths();

    let filtered_syscalls = vec![
        SyscallFilter::stdio_allow(native::SYS_write),
        SyscallFilter::allow(&[native::SYS_write], &allowed_path_list),
        SyscallFilter::with_paths_and_flags(
            native::SYS_openat,
            true,
            &allowed_path_list,
            StrMatchOp::Prefix,
            &vec![String::from("O_CREAT")],
        ),
        SyscallFilter::with_paths(
            &[
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
            ],
            true,
            &allowed_path_list,
            StrMatchOp::Prefix,
        ),
        SyscallFilter::block(&[
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
            context_matcher: None,
            flag_matcher: None,
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                log: true,
                tag: None,
            },
        }],
        logger: Some(logger),
    }
}

/// This function returns a restrictive filtering logger.
/// It blocks all syscalls except for a few allowed ones.
/// It also logs all syscalls.
#[cfg(target_arch = "x86_64")]
pub(crate) fn default_filters(logger: Box<dyn SyscallLogger>) -> FilteringLogger {
    use syscall_numbers::x86_64;

    let allowed_path_list = get_allowed_paths();

    let filtered_syscalls = vec![
        SyscallFilter::stdio_allow(x86_64::SYS_write),
        SyscallFilter::allow(&[x86_64::SYS_write], &allowed_path_list),
        SyscallFilter::with_paths_and_flags(
            native::SYS_openat,
            true,
            &allowed_path_list,
            StrMatchOp::Prefix,
            &vec![String::from("O_CREAT")],
        ),
        SyscallFilter::with_paths(
            &[
                x86_64::SYS_write,
                x86_64::SYS_writev,
                x86_64::SYS_pwritev,
                x86_64::SYS_pwritev2,
                x86_64::SYS_pwrite64,
                x86_64::SYS_unlinkat,
                x86_64::SYS_mknodat,
                x86_64::SYS_mkdirat,
                x86_64::SYS_chroot,
                x86_64::SYS_linkat,
                x86_64::SYS_symlinkat,
                x86_64::SYS_setxattr,
                x86_64::SYS_fsetxattr,
                x86_64::SYS_removexattr,
                x86_64::SYS_fremovexattr,
            ],
            true,
            &allowed_path_list,
            StrMatchOp::Prefix,
        ),
        SyscallFilter::allow(
            &[
                x86_64::SYS_open,
                x86_64::SYS_openat,
                x86_64::SYS_openat2,
                x86_64::SYS_close,
                x86_64::SYS_read,
                x86_64::SYS_readv,
                x86_64::SYS_recvmmsg,
            ],
            &vec![],
        ),
        SyscallFilter::block(&[
            x86_64::SYS_write,
            x86_64::SYS_writev,
            x86_64::SYS_pwritev,
            x86_64::SYS_pwritev2,
            x86_64::SYS_pwrite64,
            x86_64::SYS_unlink,
            x86_64::SYS_unlinkat,
            x86_64::SYS_rmdir,
            x86_64::SYS_mknod,
            x86_64::SYS_mknodat,
            x86_64::SYS_mkdir,
            x86_64::SYS_mkdirat,
            x86_64::SYS_chroot,
            x86_64::SYS_link,
            x86_64::SYS_linkat,
            x86_64::SYS_symlinkat,
            x86_64::SYS_setxattr,
            x86_64::SYS_fsetxattr,
            x86_64::SYS_removexattr,
            x86_64::SYS_fremovexattr,
            x86_64::SYS_sendfile,
            x86_64::SYS_io_setup,
            x86_64::SYS_chmod,
            x86_64::SYS_fchmod,
            x86_64::SYS_fchmodat,
            x86_64::SYS_fchmodat2,
            x86_64::SYS_chown,
            x86_64::SYS_fchown,
            x86_64::SYS_fchownat,
            x86_64::SYS_execve,
            x86_64::SYS_execveat,
            x86_64::SYS_connect,
            x86_64::SYS_listen,
            x86_64::SYS_recvfrom,
            x86_64::SYS_recvmmsg,
            x86_64::SYS_recvmsg,
            x86_64::SYS_sendto,
            x86_64::SYS_sendmsg,
            x86_64::SYS_sendmmsg,
        ]),
    ];

    let filter_map = group_filters_by_syscall(filtered_syscalls);

    FilteringLogger {
        primed: true,
        trigger_event: None,
        filters: filter_map,
        default_filters: vec![SyscallFilter {
            matcher: SyscallMatcher {
                syscall: HashSet::new(),
                args: Default::default(),
                context_matcher: None,
                flag_matcher: None,
            },
            outcome: FilterOutcome {
                action: FilterAction::Allow,
                log: false,
                tag: None,
            },
        }],
        logger: Some(logger),
    }
}
