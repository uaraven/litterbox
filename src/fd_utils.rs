use nix::libc;

pub fn is_fdcwd(dirfd: i32) -> bool {
    dirfd & libc::AT_FDCWD == libc::AT_FDCWD
}
