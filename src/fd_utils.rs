use nix::libc;

pub fn is_fdcwd(dirfd: i32) -> bool {
    return dirfd & libc::AT_FDCWD == libc::AT_FDCWD;
}
