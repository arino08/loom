//! seccomp-BPF filter and user-notification supervisor (FR-3.6, FR-3.7).
//!
//! The filter is assembled by hand from classic-BPF instructions (the program
//! is small, and hand assembly keeps it auditable). It:
//!
//! * kills the process on a foreign audit architecture and rejects the x32
//!   ABI (a classic seccomp bypass);
//! * returns `EPERM` for syscalls a build has no business making (mounting,
//!   namespace creation, ptrace, kernel keyrings, BPF, module loading,
//!   io_uring — which bypasses seccomp entirely — ...);
//! * returns `ENOSYS` for `clone3` so libc falls back to `clone`, whose flags
//!   *can* be inspected, and refuses `clone` with namespace flags;
//! * sends `socket()` for any family other than `AF_UNIX` to the supervisor,
//!   which logs and refuses it (FR-3.4 even where no network namespace is
//!   available);
//! * sends path-opening syscalls to the supervisor so that denied accesses
//!   can be *explained* (FR-3.7).
//!
//! Enforcement never depends on the supervisor's path inspection: file access
//! is enforced by the mount namespace and Landlock. The supervisor only
//! answers `EACCES` early for paths the policy denies anyway, and otherwise
//! lets the kernel decide (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`), so the
//! well-known TOCTOU caveat of user notification cannot weaken confinement.

use crate::policy::{network_verdict, syscall_verdict, AccessPolicy, Verdict};
use crate::report::Denial;
use std::os::fd::RawFd;
use std::path::PathBuf;

// ---- BPF encoding -------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const fn ret_errno(e: i32) -> u32 {
    0x0005_0000 | (e as u32 & 0xffff)
}

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 {
    16 + 8 * i // little-endian: low 32 bits first
}

fn ld(k: u32) -> Insn {
    Insn { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k }
}
fn jeq(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k }
}
fn jge(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: BPF_JMP | BPF_JGE | BPF_K, jt, jf, k }
}
fn jset(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: BPF_JMP | BPF_JSET | BPF_K, jt, jf, k }
}
fn ret(k: u32) -> Insn {
    Insn { code: BPF_RET, jt: 0, jf: 0, k }
}

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xC000_00B7;

/// Syscalls refused with EPERM, by name (for reporting) and number.
pub fn denied_syscalls() -> Vec<(&'static str, i64)> {
    use libc::*;
    let mut v: Vec<(&'static str, i64)> = vec![
        ("ptrace", SYS_ptrace),
        ("process_vm_readv", SYS_process_vm_readv),
        ("process_vm_writev", SYS_process_vm_writev),
        ("mount", SYS_mount),
        ("umount2", SYS_umount2),
        ("pivot_root", SYS_pivot_root),
        ("unshare", SYS_unshare),
        ("setns", SYS_setns),
        ("keyctl", SYS_keyctl),
        ("add_key", SYS_add_key),
        ("request_key", SYS_request_key),
        ("bpf", SYS_bpf),
        ("perf_event_open", SYS_perf_event_open),
        ("kexec_load", SYS_kexec_load),
        ("kexec_file_load", SYS_kexec_file_load),
        ("init_module", SYS_init_module),
        ("finit_module", SYS_finit_module),
        ("delete_module", SYS_delete_module),
        ("userfaultfd", SYS_userfaultfd),
        ("io_uring_setup", SYS_io_uring_setup),
        ("io_uring_enter", SYS_io_uring_enter),
        ("io_uring_register", SYS_io_uring_register),
        ("open_by_handle_at", SYS_open_by_handle_at),
        ("name_to_handle_at", SYS_name_to_handle_at),
        ("swapon", SYS_swapon),
        ("swapoff", SYS_swapoff),
        ("reboot", SYS_reboot),
        ("acct", SYS_acct),
        ("quotactl", SYS_quotactl),
        ("fsopen", SYS_fsopen),
        ("fsmount", SYS_fsmount),
        ("move_mount", SYS_move_mount),
        ("open_tree", SYS_open_tree),
        ("fanotify_init", SYS_fanotify_init),
        ("lookup_dcookie", SYS_lookup_dcookie),
        ("syslog", SYS_syslog),
        ("settimeofday", SYS_settimeofday),
        ("clock_settime", SYS_clock_settime),
        ("seccomp", SYS_seccomp),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([("iopl", SYS_iopl), ("ioperm", SYS_ioperm), ("uselib", SYS_uselib)]);
    v
}

/// Syscalls routed to the supervisor for path inspection.
pub fn path_syscalls() -> Vec<(&'static str, i64, PathArg)> {
    use libc::*;
    let mut v = vec![
        ("openat", SYS_openat, PathArg::At { path: 1, flags: Some(2) }),
        ("openat2", SYS_openat2, PathArg::At2),
        ("execve", SYS_execve, PathArg::Plain { path: 0, write: false }),
        ("mkdirat", SYS_mkdirat, PathArg::At { path: 1, flags: None }),
        ("unlinkat", SYS_unlinkat, PathArg::At { path: 1, flags: None }),
        ("renameat2", SYS_renameat2, PathArg::At { path: 3, flags: None }),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        ("open", SYS_open, PathArg::Plain { path: 0, write: false }),
        ("creat", SYS_creat, PathArg::Plain { path: 0, write: true }),
        ("mkdir", SYS_mkdir, PathArg::Plain { path: 0, write: true }),
        ("unlink", SYS_unlink, PathArg::Plain { path: 0, write: true }),
        ("rename", SYS_rename, PathArg::Plain { path: 1, write: true }),
    ]);
    v
}

#[derive(Clone, Copy, Debug)]
pub enum PathArg {
    /// `(dirfd, path, flags?)`-style; `flags` = index of O_* flags argument.
    /// Without flags, the call is a mutation (write).
    At { path: usize, flags: Option<usize> },
    /// openat2(dirfd, path, struct open_how *how, size)
    At2,
    Plain { path: usize, write: bool },
}

const NS_CLONE_FLAGS: u32 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP) as u32;

/// Build the filter program. `notify` selects user notification; without it
/// network sockets are refused directly and paths are not inspected.
pub fn build_filter(notify: bool) -> Vec<Insn> {
    build_filter_with(notify, false)
}

/// As [`build_filter`]; `allow_network` implements a user-authorised,
/// recorded exception (FR-3.8) that lets IP sockets through.
pub fn build_filter_with(notify: bool, allow_network: bool) -> Vec<Insn> {
    let mut p = vec![
        ld(OFF_ARCH),
        jeq(AUDIT_ARCH, 1, 0),
        ret(RET_KILL_PROCESS),
        ld(OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x32 syscalls have bit 30 set.
        p.push(jge(0x4000_0000, 0, 1));
        p.push(ret(ret_errno(libc::EPERM)));
    }
    for (_, nr) in denied_syscalls() {
        p.push(jeq(nr as u32, 0, 1));
        p.push(ret(ret_errno(libc::EPERM)));
    }
    // clone3 -> ENOSYS (glibc falls back to clone, whose flags we can see).
    p.push(jeq(libc::SYS_clone3 as u32, 0, 1));
    p.push(ret(ret_errno(libc::ENOSYS)));
    // clone with namespace flags -> EPERM. (x86_64 and aarch64 both pass
    // flags in arg0.)
    p.push(jeq(libc::SYS_clone as u32, 0, 4));
    p.push(ld(off_arg_lo(0)));
    p.push(jset(NS_CLONE_FLAGS, 0, 1));
    p.push(ret(ret_errno(libc::EPERM)));
    p.push(ret(RET_ALLOW));
    // socket(AF_UNIX, ...) allowed; every other family refused.
    let refuse = if allow_network {
        RET_ALLOW
    } else if notify {
        RET_USER_NOTIF
    } else {
        ret_errno(libc::EACCES)
    };
    p.push(jeq(libc::SYS_socket as u32, 0, 4));
    p.push(ld(off_arg_lo(0)));
    p.push(jeq(libc::AF_UNIX as u32, 0, 1));
    p.push(ret(RET_ALLOW));
    p.push(ret(refuse));
    if notify {
        for (_, nr, _) in path_syscalls() {
            p.push(jeq(nr as u32, 0, 1));
            p.push(ret(RET_USER_NOTIF));
        }
    }
    p.push(ret(RET_ALLOW));
    p
}

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// Install the filter on the calling thread. Returns the listener fd when
/// `notify` is set. Requires `PR_SET_NO_NEW_PRIVS` (set here).
///
/// # Safety
/// Must be called in a single-threaded process immediately before `execve`.
pub unsafe fn install(notify: bool, allow_network: bool) -> std::io::Result<Option<RawFd>> {
    let prog = build_filter_with(notify, allow_network);
    let filters: Vec<libc::sock_filter> = prog
        .iter()
        .map(|i| libc::sock_filter { code: i.code, jt: i.jt, jf: i.jf, k: i.k })
        .collect();
    let fprog = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_ptr() as *mut _,
    };
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = if notify { SECCOMP_FILTER_FLAG_NEW_LISTENER } else { 0 };
    let rc = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog as *const _);
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(if notify { Some(rc as RawFd) } else { None })
}

// ---- supervisor ----------------------------------------------------------

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

const IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
const IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;
const IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
const USER_NOTIF_FLAG_CONTINUE: u32 = 1;

fn read_cstring(pid: u32, addr: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    if addr == 0 {
        return None;
    }
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; 4096];
    let n = f.read(&mut buf).ok()?;
    let end = buf[..n].iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn read_u64(pid: u32, addr: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut b = [0u8; 8];
    f.read_exact(&mut b).ok()?;
    Some(u64::from_ne_bytes(b))
}

fn is_write_flags(flags: u64) -> bool {
    let f = flags as i32;
    (f & libc::O_ACCMODE) != libc::O_RDONLY || f & (libc::O_CREAT | libc::O_TRUNC) != 0
}

/// Supervise a listener fd until every filtered task has exited.
/// `root_prefix` maps inside paths for reporting (unused for classification).
pub fn supervise(listener: RawFd, policy: AccessPolicy, on_denial: &mut dyn FnMut(Denial)) {
    let paths = path_syscalls();
    let started = std::time::Instant::now();
    loop {
        let mut req = SeccompNotif::default();
        // SAFETY: req is a properly sized, zeroed seccomp_notif.
        let rc = unsafe { libc::ioctl(listener, IOCTL_NOTIF_RECV as _, &mut req as *mut _) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // ENOENT: all filtered tasks are gone.
        }
        let nr = req.data.nr as i64;
        let mut resp = SeccompNotifResp {
            id: req.id,
            val: 0,
            error: 0,
            flags: USER_NOTIF_FLAG_CONTINUE,
        };
        let mut verdict: Option<(Verdict, String, String)> = None;

        if nr == libc::SYS_socket {
            let fam = req.data.args[0] as i32;
            let name = match fam {
                libc::AF_INET => "AF_INET",
                libc::AF_INET6 => "AF_INET6",
                libc::AF_NETLINK => "AF_NETLINK",
                libc::AF_PACKET => "AF_PACKET",
                _ => "other",
            };
            verdict = Some((
                network_verdict(&format!("socket({name})")),
                "socket".into(),
                format!("socket family {name} ({fam})"),
            ));
        } else if let Some((name, _, arg)) = paths.iter().find(|(_, n, _)| *n == nr) {
            let (path_addr, write) = match *arg {
                PathArg::At { path, flags } => (
                    req.data.args[path],
                    flags.map(|i| is_write_flags(req.data.args[i])).unwrap_or(true),
                ),
                PathArg::At2 => (
                    req.data.args[1],
                    read_u64(req.pid, req.data.args[2]).map(is_write_flags).unwrap_or(false),
                ),
                PathArg::Plain { path, write } => {
                    let w = if *name == "open" {
                        is_write_flags(req.data.args[1])
                    } else {
                        write
                    };
                    (req.data.args[path], w)
                }
            };
            if let Some(path) = read_cstring(req.pid, path_addr) {
                // The memory read is only trustworthy if the request is still live.
                let valid = unsafe {
                    libc::ioctl(listener, IOCTL_NOTIF_ID_VALID as _, &req.id as *const u64)
                } == 0;
                if valid && path.starts_with('/') {
                    if let Some(v) = policy.classify(&PathBuf::from(&path), write) {
                        verdict = Some((v, name.to_string(), path));
                    }
                }
            }
        }

        if let Some((v, syscall, resource)) = verdict {
            resp.flags = 0;
            resp.error = -libc::EACCES;
            on_denial(Denial {
                at_ms: started.elapsed().as_millis() as u64,
                pid: req.pid,
                syscall,
                resource,
                rule: v.rule,
                requirement: v.requirement,
                reason: v.reason,
            });
        }
        // SAFETY: resp is a properly sized seccomp_notif_resp.
        unsafe {
            libc::ioctl(listener, IOCTL_NOTIF_SEND as _, &resp as *const _);
        }
    }
}

/// Human name for a denied syscall number (for reports).
pub fn syscall_name(nr: i64) -> Option<Verdict> {
    denied_syscalls()
        .into_iter()
        .find(|(_, n)| *n == nr)
        .map(|(name, _)| syscall_verdict(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny classic-BPF interpreter, enough to test the filter's decisions
    /// without loading it into the kernel.
    fn run(prog: &[Insn], nr: i64, args: [u64; 6], arch: u32) -> u32 {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&(nr as i32).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        let mut a: u32 = 0;
        let mut pc = 0usize;
        loop {
            let i = prog[pc];
            match i.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let o = i.k as usize;
                    a = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                    pc += 1;
                }
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += 1 + if a == i.k { i.jt } else { i.jf } as usize;
                }
                c if c == BPF_JMP | BPF_JGE | BPF_K => {
                    pc += 1 + if a >= i.k { i.jt } else { i.jf } as usize;
                }
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += 1 + if a & i.k != 0 { i.jt } else { i.jf } as usize;
                }
                BPF_RET => return i.k,
                other => panic!("unknown opcode {other:#x}"),
            }
        }
    }

    #[test]
    fn filter_decisions() {
        let p = build_filter(true);
        assert!(p.len() < 4096, "BPF program too long");
        let z = [0u64; 6];
        assert_eq!(run(&p, libc::SYS_read, z, AUDIT_ARCH), RET_ALLOW);
        assert_eq!(run(&p, libc::SYS_read, z, 0x4000_0003), RET_KILL_PROCESS);
        assert_eq!(run(&p, libc::SYS_ptrace, z, AUDIT_ARCH), ret_errno(libc::EPERM));
        assert_eq!(run(&p, libc::SYS_io_uring_setup, z, AUDIT_ARCH), ret_errno(libc::EPERM));
        assert_eq!(run(&p, libc::SYS_clone3, z, AUDIT_ARCH), ret_errno(libc::ENOSYS));
        let fork_like = [libc::SIGCHLD as u64, 0, 0, 0, 0, 0];
        assert_eq!(run(&p, libc::SYS_clone, fork_like, AUDIT_ARCH), RET_ALLOW);
        let newuser = [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0];
        assert_eq!(run(&p, libc::SYS_clone, newuser, AUDIT_ARCH), ret_errno(libc::EPERM));
        let unix = [libc::AF_UNIX as u64, 0, 0, 0, 0, 0];
        let inet = [libc::AF_INET as u64, 0, 0, 0, 0, 0];
        assert_eq!(run(&p, libc::SYS_socket, unix, AUDIT_ARCH), RET_ALLOW);
        assert_eq!(run(&p, libc::SYS_socket, inet, AUDIT_ARCH), RET_USER_NOTIF);
        assert_eq!(run(&p, libc::SYS_openat, z, AUDIT_ARCH), RET_USER_NOTIF);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(run(&p, 0x4000_0000 + 1, z, AUDIT_ARCH), ret_errno(libc::EPERM));

        let q = build_filter(false);
        assert_eq!(run(&q, libc::SYS_socket, inet, AUDIT_ARCH), ret_errno(libc::EACCES));
        assert_eq!(run(&q, libc::SYS_openat, z, AUDIT_ARCH), RET_ALLOW);
    }

    #[test]
    fn write_flag_detection() {
        assert!(!is_write_flags(libc::O_RDONLY as u64));
        assert!(is_write_flags(libc::O_WRONLY as u64));
        assert!(is_write_flags((libc::O_RDONLY | libc::O_CREAT) as u64));
        assert!(is_write_flags(libc::O_RDWR as u64));
    }
}
