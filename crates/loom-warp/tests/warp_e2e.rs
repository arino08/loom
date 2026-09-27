//! End-to-end: log + witnesses + client over real HTTP, including a split-view
//! attack (evaluation E6 in miniature).

use loom_core::attest::*;
use loom_core::digest::Digest;
use loom_core::http::Server;
use loom_core::keys::SecretKey;
use loom_warp::client::*;
use loom_warp::server::{Admission, LogServer};
use loom_warp::witness::Witness;
use std::collections::BTreeMap;
use std::sync::Arc;

const ORIGIN: &str = "loom.test/warp";

fn pred(pkg: &str, rebuilder: &str) -> RebuildPredicate {
    let d = Digest::of(pkg.as_bytes());
    RebuildPredicate {
        ecosystem: "aur".into(),
        package: pkg.into(),
        version: "1.0-1".into(),
        source: SourceRef {
            repo: "r".into(),
            commit: "c".into(),
            digest: Digest::of(b"s"),
        },
        outcome: Outcome::Reproducible,
        artifact: Some(d),
        variant_digests: vec![d, d],
        rebuilder: RebuilderRef {
            id: rebuilder.into(),
            org: "o".into(),
        },
        toolchain: Toolchain::new("img", BTreeMap::new(), "full"),
        observed: Observed {
            maintainer: None,
            last_modified: 0,
        },
        timestamp: 0,
        disputes: vec![],
    }
}

struct Bed {
    log: Arc<LogServer>,
    log_srv: Server,
    witnesses: Vec<(Arc<Witness>, Server)>,
    logk: SecretKey,
    rb: SecretKey,
    dir: tempfile::TempDir,
}

fn bed(n_witness: usize, evil: &[usize], split: bool) -> Bed {
    let logk = SecretKey::generate();
    let rb = SecretKey::generate();
    let dir = tempfile::tempdir().unwrap();
    let mut ws = vec![];
    for i in 0..n_witness {
        let w = Arc::new(
            Witness::new(
                &format!("w{i}.test"),
                SecretKey::generate(),
                BTreeMap::from([(ORIGIN.to_string(), logk.public())]),
                None,
                evil.contains(&i),
            )
            .unwrap(),
        );
        let s = Server::start("127.0.0.1:0", 2, w.clone().handler()).unwrap();
        ws.push((w, s));
    }
    let adm = Admission {
        rebuilders: BTreeMap::from([("thread-a".to_string(), rb.public())]),
        revokers: BTreeMap::new(),
    };
    let log = LogServer::new(
        ORIGIN,
        logk.clone(),
        ws.iter().map(|(_, s)| s.url()).collect(),
        adm,
        None,
        split,
    )
    .unwrap();
    let log_srv = Server::start("127.0.0.1:0", 4, log.clone().handler()).unwrap();
    Bed {
        log,
        log_srv,
        witnesses: ws,
        logk,
        rb,
        dir,
    }
}

impl Bed {
    fn client(&self, id: Option<&str>, threshold: usize, sub: &str) -> LogClient {
        LogClient::new(ClientConfig {
            log: TrustedLog {
                origin: ORIGIN.into(),
                key: self.logk.public(),
                url: self.log_srv.url(),
            },
            witnesses: self
                .witnesses
                .iter()
                .map(|(w, s)| TrustedWitness {
                    name: w.name.clone(),
                    key: w.public(),
                    url: Some(s.url()),
                })
                .collect(),
            threshold,
            state_dir: self.dir.path().join(sub),
            peers: vec![],
            client_id: id.map(|s| s.to_string()),
            read_only: false,
        })
    }
}

#[test]
fn honest_log_verifies() {
    let b = bed(3, &[], false);
    for p in ["a", "b", "c"] {
        b.log.add(&sign_rebuild(pred(p, "thread-a"), &b.rb).unwrap(), false).unwrap();
    }
    let c = b.client(None, 2, "c1");
    let v = c.update().unwrap();
    assert_eq!(v.checkpoint.size, 3);
    assert_eq!(v.cosigs.len(), 3);
    assert_eq!(v.records.len(), 3);
    assert_eq!(v.cross_checked.len(), 3);
    for i in 0..3 {
        v.verify_inclusion(i).unwrap();
    }
    // Grow and update again: consistency against persisted head.
    b.log.add(&sign_rebuild(pred("d", "thread-a"), &b.rb).unwrap(), false).unwrap();
    let v2 = c.update().unwrap();
    assert_eq!(v2.previous_size, Some(3));
    assert_eq!(v2.checkpoint.size, 4);
}

#[test]
fn unadmitted_signer_rejected() {
    let b = bed(1, &[], false);
    let stranger = SecretKey::generate();
    assert!(b.log.add(&sign_rebuild(pred("a", "thread-a"), &stranger).unwrap(), false).is_err());
    // Identity binding: admitted key claiming another rebuilder id.
    assert!(b.log.add(&sign_rebuild(pred("a", "thread-z"), &b.rb).unwrap(), false).is_err());
}

#[test]
fn revocation_rules() {
    let b = bed(1, &[], false);
    let rec = sign_rebuild(pred("a", "thread-a"), &b.rb).unwrap();
    let r = b.log.add(&rec, false).unwrap();
    let leaf = rec.canonical_bytes().unwrap();
    let good = RevocationPredicate {
        target_index: r.index,
        target_leaf: Digest::of(&leaf),
        reason: "compromised build host".into(),
        revoker: "thread-a".into(),
        timestamp: 1,
    };
    // Wrong digest rejected.
    let mut bad = good.clone();
    bad.target_leaf = Digest::of(b"x");
    assert!(b.log.add(&sign_revocation(bad, &b.rb).unwrap(), false).is_err());
    // Self-revocation accepted.
    b.log.add(&sign_revocation(good, &b.rb).unwrap(), false).unwrap();
    assert_eq!(b.log.size(), 2);
}

#[test]
fn threshold_not_met_is_refused() {
    let b = bed(3, &[], false);
    b.log.add(&sign_rebuild(pred("a", "thread-a"), &b.rb).unwrap(), false).unwrap();
    // Demand more cosignatures than witnesses exist.
    let c = b.client(None, 4, "c1");
    assert!(matches!(c.update(), Err(LogError::Invalid(_))));
}

#[test]
fn split_view_detected_with_honest_witnesses() {
    // 3 witnesses, one corrupt; threshold 1 so that the corrupt witness alone
    // could "satisfy" the threshold — detection must come from cross-checks.
    let b = bed(3, &[2], true);
    for p in ["a", "b"] {
        b.log.add(&sign_rebuild(pred(p, "thread-a"), &b.rb).unwrap(), false).unwrap();
    }
    // Victim sees the honest history first.
    let victim = b.client(Some("victim"), 1, "victim");
    victim.update().unwrap();

    // The log forks. The public history advances (honest witnesses cosign
    // it); the victim's fork gets a malicious record instead, which only the
    // corrupt witness is willing to cosign.
    b.log.start_fork("victim").unwrap();
    b.log.add(&sign_rebuild(pred("c", "thread-a"), &b.rb).unwrap(), false).unwrap();
    b.log.add(&sign_rebuild(pred("evil", "thread-a"), &b.rb).unwrap(), true).unwrap();

    match victim.update() {
        Err(LogError::SplitView(ev)) => {
            assert!(ev.saved_to.is_some());
        }
        Err(LogError::Invalid(_)) => {} // also acceptable: refused before cross-check
        other => panic!("split view not detected: {:?}", other.map(|v| v.checkpoint.size)),
    }

    // A bystander either sees the honest history, or — because the corrupt
    // witness now advertises the forked head — obtains two log-signed,
    // conflicting checkpoints: transferable proof of log misbehaviour.
    let bystander = b.client(None, 2, "bystander");
    match bystander.update() {
        Ok(v) => assert_eq!(v.checkpoint.size, 3),
        Err(LogError::SplitView(ev)) => assert!(ev.detail.contains("different roots")),
        Err(e) => panic!("unexpected: {e}"),
    }
}

#[test]
fn log_down_is_unavailable_not_invalid() {
    let b = bed(1, &[], false);
    let c = b.client(None, 1, "c");
    let Bed { log_srv, .. } = b;
    log_srv.shutdown();
    assert!(matches!(c.update(), Err(LogError::Unavailable(_))));
}
