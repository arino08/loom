//! Mount-namespace layout for the `full` tier (FR-3.1).
//!
//! The sandbox root is a fresh tmpfs containing only: read-only binds of the
//! system toolchain directories, a curated read-only subset of `/etc`, a
//! minimal `/dev`, a private `/proc`, a private `/tmp`, and the build
//! directory at `/build`. The user's home, `/root`, `/run`, `/var`, `/srv`,
//! `/mnt` and `/media` simply do not exist inside.

use crate::policy::{ETC_ALLOWLIST, SYSTEM_READ};
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn c(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("path without NUL")
}

fn check(rc: libc::c_int, what: &str) -> io::Result<()> {
    if rc != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

unsafe fn mount(src: Option<&Path>, dst: &Path, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> io::Result<()> {
    let s = src.map(c);
    let d = c(dst);
    let f = fstype.map(|t| CString::new(t).unwrap());
    let o = data.map(|t| CString::new(t).unwrap());
    check(
        libc::mount(
            s.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            d.as_ptr(),
            f.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
            flags,
            o.as_ref().map_or(std::ptr::null(), |x| x.as_ptr() as *const libc::c_void),
        ),
        &format!("mount {:?} -> {}", src, dst.display()),
    )
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const AT_RECURSIVE: libc::c_uint = 0x8000;

/// Recursively bind `src` at `dst` read-only, nosuid, nodev.
unsafe fn bind_ro(src: &Path, dst: &Path) -> io::Result<()> {
    mount(Some(src), dst, None, libc::MS_BIND | libc::MS_REC, None)?;
    // Prefer mount_setattr(2) (Linux 5.12+): applies recursively, so
    // submounts under e.g. /usr are read-only too.
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let d = c(dst);
    let rc = libc::syscall(
        libc::SYS_mount_setattr,
        libc::AT_FDCWD,
        d.as_ptr(),
        AT_RECURSIVE,
        &attr as *const MountAttr,
        std::mem::size_of::<MountAttr>(),
    );
    if rc == 0 {
        return Ok(());
    }
    // Fallback: remount the top-level bind read-only, preserving locked flags.
    let mut st: libc::statvfs = std::mem::zeroed();
    check(libc::statvfs(d.as_ptr(), &mut st), "statvfs")?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    if st.f_flag & libc::ST_NOEXEC != 0 {
        flags |= libc::MS_NOEXEC;
    }
    mount(None, dst, None, flags, None)
}

fn mkdir_p(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p)
}

fn touch(p: &Path) -> io::Result<()> {
    if let Some(d) = p.parent() {
        mkdir_p(d)?;
    }
    std::fs::OpenOptions::new().create(true).write(true).open(p).map(|_| ())
}

/// Replicate `host` (a symlink, directory or file) at `root/host` read-only.
unsafe fn expose(root: &Path, host: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(host) {
        Ok(m) => m,
        Err(_) => return Ok(()), // absent on this host: nothing to expose
    };
    let target = root.join(host.strip_prefix("/").unwrap());
    if meta.file_type().is_symlink() {
        if let Some(d) = target.parent() {
            mkdir_p(d)?;
        }
        let link = std::fs::read_link(host)?;
        let _ = std::os::unix::fs::symlink(link, &target);
        return Ok(());
    }
    if meta.is_dir() {
        mkdir_p(&target)?;
    } else {
        touch(&target)?;
    }
    bind_ro(host, &target)
}

/// Build the sandbox root and pivot into it. `build_fd_path` is the host build
/// directory path, bound into the sandbox at `/build`.
///
/// # Safety
/// Must run in a fresh mount namespace in a single-threaded process.
pub unsafe fn setup(build_fd_path: &Path) -> io::Result<()> {
    mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    // The new root must NOT be an ancestor of the build directory: mounting a
    // tmpfs over such an ancestor would shadow the host path the build
    // bind-mount resolves to, failing with EINVAL. A per-process mountpoint
    // under /tmp is created fresh, so it never contains an existing build dir.
    let root_buf = std::path::PathBuf::from(format!("/tmp/.loom-root.{}", libc::getpid()));
    let root = root_buf.as_path();
    mkdir_p(root)?;
    mount(Some(Path::new("tmpfs")), root, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=0755"))?;

    for d in SYSTEM_READ {
        expose(root, Path::new(d))?;
    }
    mkdir_p(&root.join("etc"))?;
    for e in ETC_ALLOWLIST {
        expose(root, &Path::new("/etc").join(e))?;
    }

    // /dev
    let dev = root.join("dev");
    mkdir_p(&dev)?;
    mount(Some(Path::new("tmpfs")), &dev, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NOEXEC, Some("mode=0755"))?;
    for n in ["null", "zero", "full", "random", "urandom", "tty"] {
        let host = Path::new("/dev").join(n);
        if host.exists() {
            let t = dev.join(n);
            touch(&t)?;
            mount(Some(&host), &t, None, libc::MS_BIND, None)?;
        }
    }
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        std::os::unix::fs::symlink(target, dev.join(name))?;
    }
    let shm = dev.join("shm");
    mkdir_p(&shm)?;
    mount(Some(Path::new("tmpfs")), &shm, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777"))?;

    // /proc (requires the PID namespace set up by our caller).
    let proc_ = root.join("proc");
    mkdir_p(&proc_)?;
    mount(Some(Path::new("proc")), &proc_, Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;

    // Private /tmp.
    let tmp = root.join("tmp");
    mkdir_p(&tmp)?;
    mount(Some(Path::new("tmpfs")), &tmp, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("mode=1777"))?;

    // The build directory, writable, nosuid/nodev.
    let build = root.join("build");
    mkdir_p(&build)?;
    mount(Some(build_fd_path), &build, None, libc::MS_BIND | libc::MS_REC, None)?;
    mount(None, &build, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV, None)?;

    // pivot_root(".", ".") then detach the old root (no leftover mounts,
    // NFR-REL-3: everything disappears with the namespace).
    let rc = libc::chdir(c(root).as_ptr());
    check(rc, "chdir new root")?;
    let dot = CString::new(".").unwrap();
    if libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) != 0 {
        return Err(io::Error::last_os_error());
    }
    check(libc::umount2(dot.as_ptr(), libc::MNT_DETACH), "detach old root")?;
    check(libc::chdir(CString::new("/").unwrap().as_ptr()), "chdir /")?;
    // Seal the root tmpfs itself.
    let _ = mount(None, Path::new("/"), None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV, None);
    Ok(())
}
