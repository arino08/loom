//! Adversarial sandbox test suite (SRS §8.1: "each of FR-3.2–3.6 has a
//! corresponding escape attempt that must fail").
//!
//! These tests create real namespaces / Landlock domains / seccomp filters,
//! so they only run when `LOOM_KERNEL_TESTS=1` is set, on a Linux host where
//! the operator permits sandbox creation:
//!
//! ```sh
//! LOOM_KERNEL_TESTS=1 cargo test -p loom-heddle --test escape
//! LOOM_KERNEL_TESTS=1 LOOM_MIN_TIER=reduced cargo test -p loom-heddle --test escape
//! ```
//!
//! The harness is custom (`harness = false`) because Heddle re-executes the
//! current binary as the sandbox init; `main` must call `maybe_init` first.

use loom_heddle::{run, Backend, SandboxSpec, Tier};
use std::path::Path;
use std::time::Duration;

fn sandbox(script: &str) -> loom_heddle::RunReport {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("attack.sh"), script).unwrap();
    let mut s = SandboxSpec::new(d.path(), vec!["/bin/bash".into(), "attack.sh".into()]);
    s.timeout = Duration::from_secs(60);
    s.min_tier = match std::env::var("LOOM_MIN_TIER").as_deref() {
        Ok("reduced") => Tier::Reduced,
        _ => Tier::Full,
    };
    let r = run(&s, &Backend::Kernel).expect("sandbox must establish");
    std::mem::forget(d);
    r
}

fn expect_blocked(name: &str, req: &str, script: &str) -> bool {
    let r = sandbox(script);
    let ok = r.exit_code != 0;
    println!(
        "{} {name:<44} [{req}] exit={} denials={} tier={}",
        if ok { "PASS" } else { "FAIL" },
        r.exit_code,
        r.denials.len(),
        r.tier.as_str()
    );
    for d in &r.denials {
        println!("       denied {} {} -> {} ({})", d.syscall, d.resource, d.rule, d.requirement);
    }
    if !ok {
        println!("       output: {}", r.log_tail.trim());
    }
    ok
}

fn main() {
    loom_heddle::maybe_init();
    if std::env::var("LOOM_KERNEL_TESTS").as_deref() != Ok("1") {
        println!("escape suite skipped (set LOOM_KERNEL_TESTS=1 on a host that permits sandboxing)");
        return;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let canary = Path::new(&home).join(".loom-escape-canary");
    std::fs::write(&canary, "SECRET-CANARY").unwrap();

    let mut all = true;
    // Sanity: a benign build succeeds.
    let r = sandbox("echo ok > out.txt && cat out.txt && gcc --version >/dev/null 2>&1 || true");
    println!("{} benign build (exit {})", if r.success() { "PASS" } else { "FAIL" }, r.exit_code);
    all &= r.success();

    all &= expect_blocked("read ~/.ssh-style canary by absolute path", "FR-3.2",
        &format!("cat {} ", canary.display()));
    all &= expect_blocked("enumerate /home", "FR-3.2", "ls /home/*/.ssh");
    all &= expect_blocked("read /etc/shadow", "FR-3.1", "cat /etc/shadow");
    all &= expect_blocked("read host ssh keys", "FR-3.1", "cat /etc/ssh/ssh_host_ed25519_key");
    all &= expect_blocked("write into /usr (LiteLLM .pth style)", "FR-3.3",
        "echo 'import os' > /usr/lib/loom-evil.pth");
    all &= expect_blocked("write into $HOME of the real user", "FR-3.3",
        &format!("echo x > {home}/.bashrc-loom-escape"));
    all &= expect_blocked("TCP connect via bash /dev/tcp", "FR-3.4",
        "exec 3<>/dev/tcp/1.1.1.1/443");
    all &= expect_blocked("DNS/UDP via bash /dev/udp", "FR-3.4",
        "exec 3<>/dev/udp/1.1.1.1/53 && echo x >&3");
    all &= expect_blocked("curl exfiltration", "FR-3.4",
        "command -v curl >/dev/null || exit 1; curl -m 5 -sS https://example.com");
    all &= expect_blocked("nested user namespace", "FR-3.6",
        "command -v unshare >/dev/null || exit 1; unshare -U true");
    all &= expect_blocked("ptrace another process", "FR-3.6",
        "command -v strace >/dev/null || exit 1; strace -f true");
    let _ = std::fs::remove_file(Path::new(&home).join(".bashrc-loom-escape"));
    all &= !Path::new("/usr/lib/loom-evil.pth").exists();

    // NFR-REL-3: nothing survives the build.
    let marker = format!("loom-escape-{}", std::process::id());
    let _ = sandbox(&format!("(sleep 300; echo {marker}) & disown; exit 0"));
    std::thread::sleep(Duration::from_millis(500));
    let survivors = std::process::Command::new("pgrep").args(["-f", "sleep 300"]).output();
    let survived = survivors.map(|o| !o.stdout.is_empty()).unwrap_or(false);
    println!("{} background process killed after build [NFR-REL-3]", if survived { "FAIL" } else { "PASS" });
    all &= !survived;

    let _ = std::fs::remove_file(&canary);
    if !all {
        eprintln!("escape suite FAILED");
        std::process::exit(1);
    }
    println!("escape suite passed");
}
