//! Heddle — Loom's least-privilege build executor (SRS §5.3).
//!
//! Every recipe, build step and install hook runs through [`run`]. There is
//! no code path that executes recipe code outside Heddle (FR-3.9).
//!
//! ## Layers (`full` tier)
//!
//! | Property | Enforced by |
//! |---|---|
//! | Only toolchain, curated `/etc`, and the build dir visible (FR-3.1) | mount namespace + pivot_root |
//! | No home / credential reads (FR-3.2) | not mounted; Landlock read allowlist |
//! | No writes outside build dir (FR-3.3) | read-only binds; Landlock |
//! | No network (FR-3.4) | empty network namespace; Landlock TCP; seccomp `socket` |
//! | Reduced syscall surface (FR-3.6) | seccomp-BPF |
//! | Every denial logged with its rule (FR-3.7) | seccomp user-notification supervisor |
//! | Nothing survives the build (NFR-REL-3) | PID namespace; process group kill |
//!
//! Where unprivileged user namespaces are disabled, the `reduced` tier keeps
//! Landlock + seccomp and reports the lost layers (NFR-MNT-3). If Landlock
//! itself is unavailable the build is refused (NFR-SEC-1).
//!
//! The binary embedding Heddle must call [`maybe_init`] first thing in
//! `main`: the sandbox is set up by re-executing the current binary.

pub mod landlock_layer;
pub mod mounts;
pub mod policy;
pub mod report;
pub mod seccomp;

pub use report::{Denial, RunReport, Tier};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INIT_ARG: &str = "__heddle-init";
const SPEC_ENV: &str = "LOOM_HEDDLE_SPEC";
const CHILD_FD: RawFd = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Host directory mounted writable as the build root.
    pub build_dir: PathBuf,
    /// Command, executed with the build root as working directory.
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// Lowest acceptable tier (policy).
    pub min_tier: Tier,
    /// User-authorised exception (FR-3.8): permit IP networking.
    pub allow_network: bool,
    pub timeout: Duration,
    /// Where to store the full build log (host path, outside the build dir).
    pub log_path: Option<PathBuf>,
}

impl SandboxSpec {
    pub fn new(build_dir: &Path, argv: Vec<String>) -> Self {
        SandboxSpec {
            build_dir: build_dir.to_path_buf(),
            argv,
            env: BTreeMap::new(),
            min_tier: Tier::Reduced,
            allow_network: false,
            timeout: Duration::from_secs(3600),
            log_path: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Kernel confinement (default).
    Kernel,
    /// Run without confinement, with `HOME` pointed at `victim_home`. Exists
    /// only so the demo can show what an *unprotected* helper (yay/paru/
    /// makepkg) would expose on hosts where creating sandboxes is not
    /// permitted. Must be selected explicitly; every report is marked.
    UnconfinedDemo { victim_home: Option<PathBuf> },
}

impl Backend {
    /// `LOOM_HEDDLE_BACKEND=kernel|unconfined-demo` (default kernel).
    pub fn from_env() -> Backend {
        match std::env::var("LOOM_HEDDLE_BACKEND").as_deref() {
            Ok("unconfined-demo") => Backend::UnconfinedDemo {
                victim_home: std::env::var_os("LOOM_DEMO_VICTIM_HOME").map(PathBuf::from),
            },
            _ => Backend::Kernel,
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Backend::Kernel => "kernel (namespaces + Landlock + seccomp)",
            Backend::UnconfinedDemo { .. } => "UNCONFINED DEMO — no kernel confinement",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The sandbox could not be established; the build did not run.
    #[error("sandbox could not be established: {0}")]
    Setup(String),
    #[error("sandbox I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
struct InitStatus {
    tier: Option<Tier>,
    layers: Vec<String>,
    reduced: Vec<String>,
    error: Option<String>,
    notify: bool,
}

fn clean_env(spec: &SandboxSpec, root: &Path) -> BTreeMap<String, String> {
    let r = root.display().to_string();
    let mut env: BTreeMap<String, String> = [
        ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin".to_string()),
        ("HOME", format!("{r}/.home")),
        ("TMPDIR", "/tmp".to_string()),
        ("LANG", "C.UTF-8".to_string()),
        ("USER", "builder".to_string()),
        ("LOGNAME", "builder".to_string()),
        ("SHELL", "/bin/bash".to_string()),
        ("TERM", "dumb".to_string()),
        ("BUILD_ROOT", r.clone()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for (k, v) in &spec.env {
        env.insert(k.clone(), v.replace("${BUILD_ROOT}", &r));
    }
    env
}

/// Run `spec` under `backend`.
pub fn run(spec: &SandboxSpec, backend: &Backend) -> Result<RunReport, SandboxError> {
    std::fs::create_dir_all(spec.build_dir.join(".home"))?;
    match backend {
        Backend::Kernel => run_kernel(spec),
        Backend::UnconfinedDemo { victim_home } => run_unconfined(spec, victim_home.as_deref()),
    }
}

struct Output {
    buf: Arc<Mutex<Vec<u8>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn collect_output(child: &mut std::process::Child) -> Output {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let mut threads = vec![];
    let out: Vec<Box<dyn Read + Send>> = vec![
        Box::new(child.stdout.take().unwrap()),
        Box::new(child.stderr.take().unwrap()),
    ];
    for mut r in out {
        let b = buf.clone();
        threads.push(std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = r.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut g = b.lock().unwrap();
                if g.len() < 32 << 20 {
                    g.extend_from_slice(&chunk[..n]);
                }
            }
        }));
    }
    Output { buf, threads }
}

fn finish_output(o: Output, log_path: Option<&Path>) -> (String, Option<PathBuf>) {
    for t in o.threads {
        let _ = t.join();
    }
    let all = o.buf.lock().unwrap().clone();
    let saved = log_path.and_then(|p| {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(p, &all).ok().map(|_| p.to_path_buf())
    });
    let tail_start = all.len().saturating_sub(4000);
    (String::from_utf8_lossy(&all[tail_start..]).into_owned(), saved)
}

fn wait_with_timeout(child: &mut std::process::Child, timeout: Duration) -> (i32, bool) {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                use std::os::unix::process::ExitStatusExt;
                let code = st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0));
                return (code, false);
            }
            Ok(None) => {}
            Err(_) => return (-1, false),
        }
        if start.elapsed() > timeout {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            return (-1, true);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run_unconfined(spec: &SandboxSpec, victim_home: Option<&Path>) -> Result<RunReport, SandboxError> {
    let started = Instant::now();
    let mut env = clean_env(spec, &spec.build_dir);
    if let Some(h) = victim_home {
        // What an unconfined helper does: the build sees the user's HOME.
        env.insert("HOME".into(), h.display().to_string());
    }
    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..])
        .env_clear()
        .envs(&env)
        .current_dir(&spec.build_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let out = collect_output(&mut child);
    let (code, timed_out) = wait_with_timeout(&mut child, spec.timeout);
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let (tail, saved) = finish_output(out, spec.log_path.as_deref());
    Ok(RunReport {
        exit_code: code,
        tier: Tier::UnconfinedDemo,
        layers: vec!["NONE — unconfined demo backend".into()],
        reduced: vec!["no kernel confinement: the build could read the user's home, use the network and write anywhere the user can".into()],
        denials: vec![],
        duration_ms: started.elapsed().as_millis() as u64,
        timed_out,
        log_tail: tail,
        log_path: saved,
    })
}

fn recv_status(sock: RawFd, timeout: Duration) -> Result<(InitStatus, Option<OwnedFd>), SandboxError> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut pfd = libc::pollfd {
        fd: sock,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
    if rc <= 0 {
        return Err(SandboxError::Setup("sandbox init did not report status".into()));
    }
    let mut buf = vec![0u8; 16 * 1024];
    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(|e| SandboxError::Setup(format!("recvmsg: {e}")))?;
    let mut fd = None;
    for c in msg.cmsgs().map_err(|e| SandboxError::Setup(e.to_string()))? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            if let Some(&f) = fds.first() {
                fd = Some(unsafe { OwnedFd::from_raw_fd(f) });
            }
        }
    }
    let n = msg.bytes;
    let status: InitStatus = serde_json::from_slice(&buf[..n])
        .map_err(|e| SandboxError::Setup(format!("bad init status: {e}")))?;
    Ok((status, fd))
}

fn run_kernel(spec: &SandboxSpec) -> Result<RunReport, SandboxError> {
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    let started = Instant::now();
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|e| SandboxError::Setup(format!("socketpair: {e}")))?;

    let spec_json = serde_json::to_string(spec).expect("spec serialises");
    let child_raw = child_sock.as_raw_fd();
    let mut cmd = Command::new("/proc/self/exe");
    cmd.arg(INIT_ARG)
        .env_clear()
        .env(SPEC_ENV, spec_json)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(child_raw, CHILD_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::fcntl(CHILD_FD, libc::F_SETFD, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop(child_sock);
    let out = collect_output(&mut child);

    let (status, listener) = match recv_status(parent_sock.as_raw_fd(), Duration::from_secs(30)) {
        Ok(x) => x,
        Err(e) => {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            let (tail, _) = finish_output(out, None);
            return Err(SandboxError::Setup(format!("{e}; init output: {tail}")));
        }
    };
    if let Some(err) = status.error {
        let _ = child.wait();
        let _ = finish_output(out, None);
        return Err(SandboxError::Setup(err));
    }
    let tier = status.tier.unwrap_or(Tier::Reduced);
    if tier < spec.min_tier {
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.wait();
        return Err(SandboxError::Setup(format!(
            "achieved tier {} is below policy minimum {}",
            tier.as_str(),
            spec.min_tier.as_str()
        )));
    }

    let denials = Arc::new(Mutex::new(Vec::<Denial>::new()));
    let sup = listener.map(|fd| {
        let d = denials.clone();
        let root = if tier == Tier::Full {
            PathBuf::from("/build")
        } else {
            spec.build_dir.clone()
        };
        let pol = policy::AccessPolicy::for_build(&root, &[]);
        std::thread::spawn(move || {
            seccomp::supervise(fd.as_raw_fd(), pol, &mut |den| d.lock().unwrap().push(den));
            drop(fd);
        })
    });

    let (code, timed_out) = wait_with_timeout(&mut child, spec.timeout);
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    if let Some(h) = sup {
        let _ = h.join();
    }
    let (tail, saved) = finish_output(out, spec.log_path.as_deref());
    let denials = denials.lock().unwrap().clone();
    Ok(RunReport {
        exit_code: code,
        tier,
        layers: status.layers,
        reduced: status.reduced,
        denials,
        duration_ms: started.elapsed().as_millis() as u64,
        timed_out,
        log_tail: tail,
        log_path: saved,
    })
}

// ---------------------------------------------------------------- init side

/// Call first thing in `main`. If this process is a Heddle init, it sets up
/// confinement and `exec`s the build; it never returns.
pub fn maybe_init() {
    let mut args = std::env::args();
    let _ = args.next();
    if args.next().as_deref() == Some(INIT_ARG) {
        init_main();
    }
}

fn send_status(st: &InitStatus, fd: Option<RawFd>) {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    let body = serde_json::to_vec(st).unwrap_or_default();
    let iov = [std::io::IoSlice::new(&body)];
    let fds;
    let cmsgs: Vec<ControlMessage> = match fd {
        Some(f) => {
            fds = [f];
            vec![ControlMessage::ScmRights(&fds)]
        }
        None => vec![],
    };
    let _ = sendmsg::<()>(CHILD_FD, &iov, &cmsgs, MsgFlags::empty(), None);
}

fn init_main() -> ! {
    let result = (|| -> anyhow::Result<std::convert::Infallible> {
        let spec: SandboxSpec = serde_json::from_str(&std::env::var(SPEC_ENV)?)?;
        init_inner(&spec)
    })();
    let err = match result {
        Err(e) => e.to_string(),
        Ok(never) => match never {},
    };
    send_status(
        &InitStatus {
            tier: None,
            layers: vec![],
            reduced: vec![],
            error: Some(err),
            notify: false,
        },
        None,
    );
    std::process::exit(125);
}

fn write_file(p: &str, s: &str) -> std::io::Result<()> {
    std::fs::write(p, s)
}

fn init_inner(spec: &SandboxSpec) -> anyhow::Result<std::convert::Infallible> {
    use std::ffi::CString;
    let mut layers = vec![];
    let mut reduced = vec![];
    let mut tier = Tier::Full;

    // Open the build dir before any namespace/mount changes.
    let build_c = CString::new(spec.build_dir.as_os_str().as_encoded_bytes())?;
    let build_fd = unsafe { libc::open(build_c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY) };
    if build_fd < 0 {
        anyhow::bail!("cannot open build dir: {}", std::io::Error::last_os_error());
    }

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWCGROUP;
    if !spec.allow_network {
        flags |= libc::CLONE_NEWNET;
    }
    if unsafe { libc::unshare(flags) } != 0 {
        let e = std::io::Error::last_os_error();
        if spec.min_tier > Tier::Reduced {
            anyhow::bail!("cannot create namespaces ({e}) and policy requires the full sandbox tier");
        }
        tier = Tier::Reduced;
        reduced.push(format!(
            "unprivileged user namespaces unavailable ({e}): no mount/network/PID isolation; relying on Landlock + seccomp"
        ));
    } else {
        write_file("/proc/self/setgroups", "deny")?;
        write_file("/proc/self/uid_map", &format!("{uid} {uid} 1\n"))?;
        write_file("/proc/self/gid_map", &format!("{gid} {gid} 1\n"))?;
        // The next child is PID 1 of the new PID namespace.
        match unsafe { libc::fork() } {
            -1 => anyhow::bail!("fork: {}", std::io::Error::last_os_error()),
            0 => {}
            pid => {
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
                let code = if libc::WIFEXITED(st) {
                    libc::WEXITSTATUS(st)
                } else {
                    128 + libc::WTERMSIG(st)
                };
                std::process::exit(code);
            }
        }
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            let h = b"heddle";
            libc::sethostname(h.as_ptr() as *const libc::c_char, h.len());
            mounts::setup(Path::new(&format!("/proc/self/fd/{build_fd}")))?;
        }
        layers.push("namespaces: user, mount (pivot_root to minimal tmpfs root), network (empty), PID, IPC, UTS, cgroup".into());
        if spec.allow_network {
            reduced.push("network namespace skipped: user-authorised network exception (FR-3.8)".into());
        }
    }
    unsafe { libc::close(build_fd) };

    let root = if tier == Tier::Full {
        PathBuf::from("/build")
    } else {
        spec.build_dir.clone()
    };
    let pol = policy::AccessPolicy::for_build(&root, &[]);
    let ll = landlock_layer::apply(&pol, spec.allow_network)?;
    layers.push(ll.description);
    reduced.extend(ll.reduced);

    let env = clean_env(spec, &root);
    std::env::set_current_dir(&root)?;
    let argv: Vec<CString> = spec
        .argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()?;
    let envp: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<Result<_, _>>()?;
    let prog = resolve(&spec.argv[0], env.get("PATH").map(|s| s.as_str()).unwrap_or("/usr/bin"))?;

    // SAFETY: single-threaded; exec follows immediately.
    let listener = unsafe { seccomp::install(true, spec.allow_network) }
        .map_err(|e| anyhow::anyhow!("seccomp: {e}"))?;
    layers.push("seccomp-BPF: dangerous syscalls refused, x32 blocked, clone3→ENOSYS, supervisor explains denials".into());
    send_status(
        &InitStatus {
            tier: Some(tier),
            layers,
            reduced,
            error: None,
            notify: listener.is_some(),
        },
        listener,
    );
    if let Some(l) = listener {
        unsafe { libc::close(l) };
    }
    unsafe { libc::close(CHILD_FD) };

    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|a| a.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    unsafe { libc::execve(prog.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr()) };
    anyhow::bail!("execve {}: {}", spec.argv[0], std::io::Error::last_os_error())
}

fn resolve(prog: &str, path: &str) -> anyhow::Result<std::ffi::CString> {
    let p = if prog.contains('/') {
        PathBuf::from(prog)
    } else {
        path.split(':')
            .map(|d| Path::new(d).join(prog))
            .find(|c| c.exists())
            .ok_or_else(|| anyhow::anyhow!("{prog} not found on PATH inside sandbox"))?
    };
    Ok(std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_is_clean_and_rooted() {
        let mut s = SandboxSpec::new(Path::new("/host/b"), vec!["true".into()]);
        s.env.insert("SRC".into(), "${BUILD_ROOT}/src".into());
        let e = clean_env(&s, Path::new("/build"));
        assert_eq!(e["HOME"], "/build/.home");
        assert_eq!(e["SRC"], "/build/src");
        assert!(!e.contains_key("SSH_AUTH_SOCK"));
    }

    #[test]
    fn tier_order() {
        assert!(Tier::Full > Tier::Reduced);
        assert!(Tier::Reduced > Tier::UnconfinedDemo);
    }

    /// Unconfined demo backend runs commands and captures output.
    #[test]
    fn unconfined_backend_runs() {
        let d = tempfile::tempdir().unwrap();
        let mut s = SandboxSpec::new(d.path(), vec!["/bin/sh".into(), "-c".into(), "echo hi; echo $HOME".into()]);
        s.timeout = Duration::from_secs(10);
        let r = run(&s, &Backend::UnconfinedDemo { victim_home: None }).unwrap();
        assert!(r.success());
        assert!(r.log_tail.contains("hi"));
        assert_eq!(r.tier, Tier::UnconfinedDemo);
    }
}
