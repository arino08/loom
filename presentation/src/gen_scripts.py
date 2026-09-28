"""Generate the four presenter speaking scripts (PDF)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from pdfkit import *  # noqa

OUT = "/home/user/loom/presentation"
os.makedirs(OUT, exist_ok=True)
W = 174 * mm

ORDER = [
    ["Part", "Presenter", "Slides", "Time", "What it covers"],
    ["1", "Presenter 1", "1 – 7", "≈ 8 min", "Title, abstract, introduction, problem & objectives, literature review (2 slides), research gap"],
    ["2", "Presenter 2", "8 – 11", "≈ 8 min", "System architecture, install flow, attestation & logging flow, cryptography & the Warp log"],
    ["3", "Presenter 3", "12 + live demo A", "≈ 9 min", "Heddle sandbox & Weave policy engine; live scenarios 1, 2, 3, 4, 7"],
    ["4", "Presenter 4", "live demo B + 13 – 16", "≈ 9 min", "Live scenarios 5, 6, 8 and the full-run console; results, demo recap, conclusion, references, Q&A"],
]

NUMBERS = [
    ["Fact", "Value", "Where it comes from"],
    ["Malicious cases blocked (AC-1)", "9 / 9 (100%)", "loom-eval E1, labelled incident corpus"],
    ["Benign packages blocked (AC-2)", "0 / 7 (0%)", "loom-eval E2"],
    ["Best single mechanism (AC-4)", "catches 3 of 9 (sandbox)", "loom-eval E4 ablation"],
    ["Policy decision time", "8.3 µs (target < 500 ms)", "loom-eval E5, release build"],
    ["Ed25519 attestation verification", "60 µs (target < 100 ms)", "loom-eval E5, release build"],
    ["Split views detected (AC-6)", "200 / 200", "loom-eval E6"],
    ["Sink hits, same malicious build", "0 confined vs 1 unconfined", "demo scenario 7"],
    ["Code base", "11 Rust crates, ~12,700 lines, 75 automated tests", "cargo test --workspace"],
    ["Default policy", "k = 2 attestations, 2-of-3 witnesses, 72 h quarantine, continuity change = block", "SRS Appendix A"],
    ["Deployment in the demo", "mock AUR :7700, Warp :7710, witnesses :7721-3, rebuilders/peers :7731-3, console :7790", "demo/run.sh"],
]


def header(n, role, slides, time, handover_to, handover_from):
    s = [P("LOOM · MAJOR PROJECT REVIEW · SPEAKER SCRIPT", "eyebrow"),
         P(f"Presenter {n} — {role}", "title"),
         P(f"Slides {slides} · target time {time}", "subtitle"),
         boxed([P("<b>Your name:</b> ____________________________ &nbsp;&nbsp; <b>Roll no.:</b> ______________", "body"),
                P(f"<b>You take over from:</b> {handover_from} &nbsp;&nbsp;·&nbsp;&nbsp; <b>You hand over to:</b> {handover_to}", "body")], SOFT),
         Spacer(1, 8),
         P("How to use this script", "h2"),
         P("The <b>Say</b> text is written to be spoken at a natural pace (about 130 words a minute). You do not need to read it word for word: "
           "learn the first and last sentence of each slide and the numbers, and speak the middle in your own words. "
           "<i>Italic cues</i> tell you what to point at. Everything technical here matches the code in the repository.", "body"),
         P("The whole talk at a glance", "h2"),
         table(ORDER, [12 * mm, 24 * mm, 30 * mm, 18 * mm, W - 84 * mm]),
         Spacer(1, 6)]
    return s


def slide(num, title, time, say, cues=None, terms=None):
    out = [CondPageBreak(60 * mm), P(f"Slide {num} · {title} <font color='#5B6275' size='10'>({time})</font>", "h1")]
    if cues:
        out += [P("On screen: " + cues, "cue")]
    out += [P("<b>Say</b>", "h3")] + [P(p, "say") for p in say]
    if terms:
        out += [boxed([P("<b>Terms to be ready to explain:</b> " + terms, "small")], SOFT2)]
    return out


def handoff(text):
    return [Spacer(1, 6), boxed([P("<b>Handover line</b>", "h3"), P(text, "say")], AMBERSOFT, AMBER)]


def qa(items):
    out = [PageBreak(), P("Questions the jury is likely to ask you", "h1"),
           P("Answer in two or three sentences, then stop. If a question belongs to another presenter's area, say "
             "“My teammate covered that, [name] can answer” and hand it over.", "body")]
    for q, a in items:
        out.append(KeepTogether([P("Q. " + q, "q"), P(a, "a")]))
    return out


def numbers():
    return [Spacer(1, 10), P("Numbers every presenter must know", "h1"), table(NUMBERS, [52 * mm, 58 * mm, W - 110 * mm])]


def demo_step(title, cmd, expect, say, fallback=None):
    out = [CondPageBreak(55 * mm), P(title, "h2"), code(cmd)]
    out += [P("<b>What you will see</b>", "h3")] + bullets(expect)
    out += [P("<b>Say</b>", "h3")] + [P(p, "say") for p in say]
    if fallback:
        out += [P("If it misbehaves: " + fallback, "cue")]
    return out


SETUP = [
    P("Before the jury arrives (whoever owns the laptop)", "h2"),
    code("cd loom\ncargo build                          # once; takes ~30 s\npython3 demo/fixtures/genfix.py      # materialise package fixtures\ndemo/run.sh                          # full dry run, ~70 s; must end with 'demo complete'\ncargo run -p loom-eval               # optional: prints 'ALL CHECKED ACCEPTANCE CRITERIA PASS'"),
    *bullets([
        "The first line of every run prints <b>sandbox tier on this host: full</b>. If it says <i>reduced</i>, the host has unprivileged user namespaces disabled; the demo still works, but say “reduced tier” when you describe the sandbox.",
        "Make the terminal font large (at least 16 pt) and the window at least 100 columns wide; the output is designed for 80 columns.",
        "Open a browser tab at <b>http://127.0.0.1:7790</b> (the live console; it is up only while a scenario is running with LOOM_HOLD=1).",
        "Open <b>docs/demo-report.html</b> in a second tab. It is a saved snapshot of a full run and is your backup if anything fails live.",
        "demo/run.sh frees its own ports, so a crashed earlier run is not a problem. Never run <i>pkill -f loomd</i> by hand.",
        "Each scenario is independent: <b>LOOM_HOLD=1 demo/run.sh &lt;scenario&gt;</b> runs one scenario in 6–10 seconds, then keeps the services and console alive until you press <b>Ctrl-C</b>.",
    ]),
]


# =========================================================================== Presenter 1
def p1():
    st = header(1, "Introduction & research", "1 – 7", "≈ 8 minutes", "Presenter 2 (architecture)", "— (you open the presentation)")
    st += slide(1, "Title", "30 s", [
        "Good morning. We are Group 14: Aiman Haque, Zoya Mulani, Aariz Sheikh and Yusuf Aslam. Our major project is <b>Loom: a decentralised, verifying package manager for the Arch User Repository</b>, guided by [guide's name].",
        "In one sentence: Loom lets you install community software from the AUR safely, without needing any cooperation from the AUR or from the people who publish packages there. "
        "It does that by containing every build, by demanding independent, publicly logged evidence before anything is installed, and by noticing when the people behind a package change.",
    ], "the woven pattern on the right is our logo motif; the name Loom and its parts (Warp, Weft, Heddle, Thread, Shuttle) come from weaving.")
    st += slide(2, "Abstract and index terms", "1 min", [
        "The abstract follows the IEEE format. The key idea is in the second sentence: community repositories run unreviewed build scripts with your full privileges, and they install whatever a maintainer publishes.",
        "Loom is <b>not a malware scanner</b>. It combines five independent mechanisms: a least-privilege build sandbox called Heddle; Thread and Weave, which only accept an artifact when several independent rebuilders reproduce it bit-for-bit; a temporal quarantine for brand-new versions; continuity checks that notice a change of maintainer or a rewritten history; and Warp, a transparency log cosigned by independent witnesses.",
        "On the right are four results from our own evaluation, which Presenter 4 will show in detail: nine of nine malicious cases blocked, zero of seven benign packages blocked, two hundred of two hundred split-view attacks detected, and sixty microseconds to verify an attestation signature.",
    ], "point at the four numbers on the right as you mention them.", "AUR, PKGBUILD, attestation, transparency log, witness, split view.")
    st += slide(3, "Installing from the AUR means running a stranger's script", "1 min 15 s", [
        "Let me show why this problem matters. On the left is what happens when you type <b>yay -S</b> some package. The helper downloads a PKGBUILD from the AUR's git server. makepkg then <b>runs that PKGBUILD, a shell script, as your own user</b>. "
        "Inside its build function it can read your SSH keys, your cloud credentials and your browser data, and it can open network connections. Only after that does pacman install the result as root, running the package's install hooks as root too.",
        "Nobody reviews uploads to the AUR, nothing is signed, and when a maintainer abandons a package, <b>anyone can adopt it</b> and push a new version to every existing user. Miller et al. [6] showed that abandonment is common and that users have no plan for it. "
        "The XZ Utils backdoor in 2024 [5] is the textbook case: a patient takeover of maintainership followed by a payload hidden in the build process.",
        "On the right, the scale, all from peer-reviewed work since 2023: 107 distinct attack vectors on open-source supply chains [1]; 24,356 malicious packages in the largest in-the-wild dataset [4]; three quarters of malicious PyPI packages reached users <b>through source installation</b> [3], which is exactly how the AUR works; and fewer than one percent of packages sandbox themselves [15]. "
        "So containment has to be enforced by the package manager. It cannot be left to package authors.",
    ], "trace the four steps top to bottom; steps 3 and 4 are red because that is where the damage happens.", "orphan adoption, makepkg, pacman hooks, source installation.")
    st += slide(4, "Problem, objectives and the five defences", "1 min 15 s", [
        "Our problem statement is in the dark box: install AUR packages only when there is independent, publicly verifiable evidence that the artifact matches its source; contain every build under least privilege; and detect changes of publishing authority; all with <b>no cooperation</b> from the AUR, its maintainers or upstream. That last constraint is what makes the problem hard.",
        "We turned that into five objectives, and each is met by one subsystem. One: contain every build, handled by <b>Heddle</b>. Two: verify, don't trust, handled by <b>Thread and Weave</b>. Three: slow down fast attacks, handled by <b>Quarantine</b>. Four: notice who changed, handled by <b>Continuity</b>. Five: make the evidence public, handled by <b>Warp</b>. "
        "A sixth objective runs through all of them: every decision must explain which rule fired and how to proceed.",
        "The mechanisms are deliberately independent, so an attacker who beats one still faces four. The footer states what we do not claim, for example that if every rebuilder faithfully reproduces malicious source code, reproducibility alone cannot tell. We state this openly because it is exactly why we have five mechanisms and not one.",
    ], "walk the five cards left to right; each has an objective at the top and the attack it counters at the bottom.", "threat model, least privilege, k-of-n, independent rebuilders.")
    st += slide(5, "Literature review (1 of 2)", "1 min", [
        "We reviewed sixteen papers, all from 2023 onwards and from venues such as IEEE S&amp;P, ACM CCS, USENIX Security, NDSS, ASE, FSE, ICSE, MSR and DSN. Each row gives the contribution and the gap Loom fills.",
        "The first four characterise the threat. Ladisa et al. [1] built the reference taxonomy of supply-chain attacks. Ladisa [2], Guo [3] and Zhou [4] study malicious packages; their detectors are useful but <b>probabilistic</b>, so an attacker can adapt, which is why Loom contains and verifies instead of classifying.",
        "Przymus and Durieux [5] reconstruct the XZ Utils attack, and Miller et al. [6] study abandonment. Together they tell us the attack surface is changes of authority plus build-time payloads, which our continuity checks and sandbox target. "
        "Schorlemmer [7] and Merrill [8] cover signing: signing tells you <b>who</b> published, not whether the artifact matches its source, and it needs registry cooperation that the AUR does not offer.",
    ], "don't read the table; pick the highlighted phrases.")
    st += slide(6, "Literature review (2 of 2)", "1 min", [
        "The second half covers the building blocks we use. Abu Ishgair et al. [9] argue for layered defences evaluated by the attacks they actually stop, which is exactly how we evaluate Loom, with an ablation study. Tamanna et al. [10] show that provenance frameworks like SLSA stall because they need the producer's buy-in; Loom produces its own provenance through independent rebuilders.",
        "Malka, Zacchiroli and Zimmermann [11, 12] show that independent rebuilding is feasible at scale: over 700,000 Nix packages rebuilt. But nobody turns reproducibility into an install-time decision, which is what our Weave engine does.",
        "Parakeet [13] and OPTIKS [14] show that transparency logs work in production without any blockchain; Warp applies that idea to build attestations. Finally, Alhindi and Hallett [15] found that sandboxing is rarely adopted by developers, and Brandt et al. [16] validate the Landlock-plus-seccomp combination that Heddle relies on.",
    ])
    st += slide(7, "Research gap", "1 min", [
        "This table is the conclusion of our review. Each column is a class of existing solution and each row a property. yay and paru add convenience, not verification. A clean chroot build helps a little with isolation. Malware detectors are probabilistic. Signing needs registry cooperation. Reproducible-builds research measures reproducibility but never makes an install decision.",
        "Only the last column has every property, and it is the only one that also <b>works with zero registry cooperation</b>. That combination, verified at install time on the client, is our contribution.",
    ], "run your finger down the green Loom column, then across the bottom row.")
    st += handoff("“So that is the problem and the gap. [Presenter 2] will now show you how Loom is built: its architecture, and what happens step by step when you install a package.”")
    st += qa([
        ("Why the AUR and not npm or PyPI?", "The AUR is the extreme case: installing means executing the build script on your machine, nothing is signed, and orphan adoption is a built-in feature. If Loom works there it works anywhere, and the design keeps all AUR knowledge behind one interface, so npm or PyPI backends need no changes to the security engines (requirement NFR-MNT-1)."),
        ("How is this different from yay or paru?", "yay and paru are convenience wrappers around makepkg: they fetch and build, with no sandbox, no verification and no history. Loom replaces them at the point of installation and adds all five defences."),
        ("Why not just use machine-learning malware detection?", "Detection is probabilistic and adversaries adapt to it [2]. Loom does not guess whether code is malicious; it confines what code can do and requires independent evidence that the artifact matches the source. The two approaches are complementary, and a detector could feed Loom's advisory input in future."),
        ("Why not use signing, such as Sigstore?", "Signing requires publishers or the registry to take part, and the AUR offers neither (our constraint CON-1). Signing also proves who published an artifact, not that it matches its source [7]. Loom obtains that evidence itself through independent rebuilders."),
        ("What exactly is novel?", "The combination, done entirely client-side without cooperation: sandboxed builds, k-of-n reproducible attestations, a witnessed log, continuity drawn from the log's own history (so first-time installers are protected too), an install-placement policy, and failing closed on hostile sandbox denials even when a build exits successfully."),
        ("Are your references recent and credible?", "All sixteen are from 2023 to 2026, mostly peer-reviewed at top venues: IEEE S&amp;P, ACM CCS, USENIX Security, NDSS, ASE, ESEC/FSE, ICSE, MSR, DSN, ACSAC and HICSS. Two are recent arXiv preprints, labelled as such."),
    ])
    st += numbers()
    return st


# =========================================================================== Presenter 2
def p2():
    st = header(2, "Architecture, flows & cryptography", "8 – 11", "≈ 8 minutes", "Presenter 3 (sandbox & policy, live demo)", "Presenter 1 (research gap)")
    st += slide(8, "System architecture", "2 min", [
        "Here is the whole system. The user talks only to the <b>loom client</b>, the dashed box, which is our trusted computing base. Inside it: <b>Weave</b>, the policy engine that makes decisions; <b>Heddle</b>, the build sandbox; the <b>Warp client</b>, which verifies the log; <b>Shuttle</b>, which fetches artifacts by hash; and the AUR backend, the only part that knows anything about the AUR.",
        "Outside are independent parties. The <b>AUR</b> is read-only to us: we read recipes, and we never execute a recipe to learn its metadata; we parse the .SRCINFO file instead. Three <b>Thread rebuilders</b>, run by different organisations with different toolchains, rebuild every package and sign what they built. Those signed attestations go into the <b>Warp log</b>, and three <b>witnesses</b> cosign the log's checkpoints. <b>Shuttle peers</b> serve the built artifacts by content address.",
        "At the bottom, pacman performs the final install and the Linux kernel provides the sandbox primitives. The key point is the note on the right: every arrow into the client carries data that is verified by a hash or a signature before it is used. If any verification fails, Loom refuses. It never falls back to trusting the data.",
    ], "trace AUR → rebuilders → Warp → witnesses, then the long indigo arrow back into the client.", "trusted computing base, content address, attestation, checkpoint, cosignature.")
    st += slide(9, "Install flow: decide before anything runs", "2 min", [
        "This is what happens when you type <b>loom install</b>. Step one resolves the package and its dependencies, dependencies first. Step two fetches the recipe and parses .SRCINFO, and no package code runs. Step three gathers evidence: it verifies the log, collects the attestations, and checks continuity, quarantine and security advisories.",
        "Step four is the Weave decision. If anything fails, Loom refuses right there and prints the rule that fired, the evidence and the exact command to proceed if the user accepts the risk. <b>At that point no package code has executed.</b>",
        "If it is allowed, step five obtains the artifact. Loom prefers the <b>attested artifact</b>, fetched from peers by its SHA-256 hash. So when k independent rebuilders agree, the PKGBUILD never runs on the user's machine at all. Only if no peer can serve it does Loom build locally, inside Heddle.",
        "Then Loom inspects what the package would install, strips its install script so pacman can never run it as root, and re-evaluates, because the files themselves can still cause a block, for example a pacman hook. Finally it installs, runs any install script inside the sandbox, and records a baseline for future continuity checks.",
    ], "follow the numbers: top row left to right, the diamond, then the bottom row right to left.", "FR-3.9 (never execute a build script outside confinement), content addressing, .INSTALL.")
    st += slide(10, "Attestation and logging flow (sequence)", "1 min 45 s", [
        "This sequence diagram shows where the evidence comes from; time runs downward. A rebuilder fetches the recipe with its pinned sources and <b>builds it twice</b> with deliberately different time zones, locales, umasks and build paths. That is the reprotest technique from the Reproducible Builds project. If both SHA-256 digests match, the build is reproducible.",
        "The rebuilder then signs an in-toto statement, wrapped in a DSSE envelope, with its own Ed25519 key. The statement binds the artifact hash to the source commit and to the rebuilder's identity and toolchain. It submits this to Warp.",
        "Warp checks that the signer is an admitted rebuilder, appends the record as a new leaf, signs a new checkpoint and sends it to each witness together with a <b>consistency proof</b>. A witness verifies that proof against the last checkpoint it cosigned and only then returns a cosignature.",
        "Finally the client fetches the checkpoint, requires at least two of the three cosignatures, checks consistency with the head it saved last time, and verifies inclusion of every attestation it uses.",
    ], "move down the numbered arrows 1 to 10.", "reprotest, in-toto, DSSE, consistency proof, inclusion proof.")
    st += slide(11, "Cryptography and the Warp transparency log", "2 min", [
        "We invent no cryptography; that is a hard constraint in our requirements. Everything uses two audited Rust libraries: ed25519-dalek and sha2. <b>SHA-256</b> gives every artifact and record a content address. <b>Ed25519</b> signs attestations, checkpoints and cosignatures, and we verify with verify_strict, which rejects malleable and small-order signatures.",
        "Two subtler choices matter. <b>DSSE's pre-authentication encoding</b> signs the payload type and the body, each prefixed with its length, so nothing can be spliced or reinterpreted; and because the in-toto <i>predicate type</i> is inside the signed body, a signature on an attestation can never be reused as a signature on a revocation. And <b>canonical JSON</b>, with sorted keys and no floating-point numbers, means the same record always produces the same bytes, so anyone can re-verify a signature.",
        "On the right is the Merkle tree. Leaves are hashed with a 0x00 prefix and interior nodes with 0x01, as in RFC 6962; that domain separation stops an attacker from passing off an interior node as a leaf. To prove that record d2 is in the log, the server sends only the three amber sibling hashes: log base two of eight. With a million records that is only twenty hashes.",
        "Why witnesses? A dishonest log could show the victim one history and everyone else another: a <b>split view</b>. A witness only cosigns after checking consistency with what it cosigned before, so an honest witness vouches for one linear history. With two of three witnesses required, any two quorums share at least one witness, so a split view is <b>prevented</b> while at most one witness colludes, and detected beyond that.",
    ], "point at the code box when you say 0x00 and 0x01; trace d2 → h1.1 → h2.0 → root, then the three amber boxes.", "Ed25519, SHA-256, DSSE PAE, canonical JSON, RFC 6962, inclusion and consistency proofs, quorum intersection 2t − n.")
    st += handoff("“So the evidence is signed, logged and witnessed. What stops a malicious build in the first place, and how does Loom turn all this evidence into a decision? [Presenter 3] will explain Heddle and Weave, and then show you all of this running live.”")
    st += qa([
        ("Why a Merkle tree and not a blockchain?", "We need append-only history with cheap proofs, not consensus among strangers. A Merkle log gives O(log n) inclusion and consistency proofs, and a few independent witnesses prevent equivocation cheaply. Parakeet [13] and OPTIKS [14] show this works in production. Our requirements also rule out blockchain and tokens (CON-2)."),
        ("What exactly does a witness check before cosigning?", "It receives the new checkpoint, the size it last cosigned, and a consistency proof between the two. It verifies the log's signature and the proof; if the new tree does not extend the old one it refuses with a conflict. Otherwise it signs a cosignature/v1 message that includes a timestamp. The witness key uses a different algorithm byte (0x04) from the log key (0x01), so the two roles can never be confused."),
        ("What can a malicious log operator still do?", "It cannot delete or rewrite records without breaking consistency proofs, and it cannot show a victim a different history without the honest witnesses refusing, which is scenario 8 of our demo. It can refuse to include a record or go offline; that affects availability, not integrity, and the client then makes a policy decision instead of crashing (NFR-REL-2)."),
        ("Why Ed25519 rather than RSA or ECDSA?", "Ed25519 signatures are deterministic, so there is no per-signature random nonce that can leak the key if the RNG is bad, as happened with ECDSA in the past. Keys are 32 bytes, signatures 64 bytes, verification takes about 60 µs in our benchmark, and it is standardised in RFC 8032. verify_strict additionally rejects non-canonical and small-order signatures."),
        ("Why SHA-256 and not BLAKE3?", "SHA-256 is FIPS 180-4 standard, it is what RFC 6962 Merkle trees, in-toto and pacman already use, and it is fast enough: hashing is never our bottleneck. Interoperability and auditability matter more here than raw speed."),
        ("What is DSSE's PAE, and why not just sign the JSON?", "PAE is a length-prefixed encoding: 'DSSEv1', the length and value of the payload type, then the length and value of the body. Signing that binds the type to the content and, thanks to length-prefixing, removes any ambiguity about where one ends and the other begins, so bytes cannot be spliced between messages. Inside the body, the in-toto statement carries its predicate type (rebuild or revocation), which is covered by the signature and checked on decode, so an attestation can never be reinterpreted as a revocation."),
        ("What if a rebuilder's private key is stolen?", "One compromised rebuilder is below the threshold: Weave needs k independent attestations, and any self-verified rebuilder that reproduces a different digest blocks the install outright (FR-6.4). The key can be revoked with a revocation record that names the leaf by index and digest; revocations stay in history but invalidate the attestation for every client."),
        ("How does the client verify inclusion?", "It recomputes the path from the leaf hash up to the root using the sibling hashes in the proof and checks that it equals the root in the witness-cosigned checkpoint. Loom goes further: it mirrors every record and recomputes the whole root locally, so the log cannot hide records, and in particular cannot hide revocations."),
    ])
    st += numbers()
    return st


# =========================================================================== Presenter 3
def p3():
    st = header(3, "Heddle, Weave & live demo (part A)", "12 + live scenarios 1, 2, 3, 4, 7", "≈ 9 minutes (4 min slide, 5 min demo)", "Presenter 4 (demo part B)", "Presenter 2 (cryptography & Warp)")
    st += slide(12, "Heddle sandbox and Weave policy engine", "3 min 30 s", [
        "On the left is <b>Heddle</b>, our build sandbox, made of three nested layers. The outer layer is Linux <b>namespaces</b>: the build gets its own user, mount, network, process, IPC, hostname and cgroup namespaces. We pivot_root into a fresh, empty temporary filesystem that contains only the toolchain, read-only, and the build directory. Your home directory does not exist inside, and the network namespace is empty.",
        "The middle layer is <b>Landlock</b>, a Linux security module that any unprivileged process can apply to itself. It is a kernel allow-list for files, TCP ports and inter-process communication. The inner layer is a <b>seccomp-BPF</b> filter that refuses dangerous system calls such as mount, ptrace, bpf and io_uring, and hands socket and file-open calls to a supervisor that <b>explains</b> each denial in the terms of our requirements.",
        "Tiers: if the host disallows user namespaces we drop to the reduced tier, Landlock plus seccomp, and say so. If even Landlock is missing, we <b>refuse to build</b>. There is never an unconfined fallback.",
        "The red box is a change we made while hardening the prototype. A malicious script can wrap its payload in <b>|| true</b> so that the build still succeeds after the sandbox denies it. We now treat any attempt to read credentials, or to use the network, as hostile: rebuilders refuse to attest such a build, and Weave blocks it, even when it exits with success.",
        "On the right is <b>Weave</b>. It is a pure function from the policy and the evidence to a decision. It evaluates all nine rules and reports every violation, each with evidence and a remediation. Continuity runs first, because a change of maintainer can tighten the rules that follow.",
        "The most interesting algorithm is <b>independence</b>. Two attestations are correlated if they share a rebuilder, an organisation or a toolchain; the toolchain ID is a SHA-256 hash of the build image and its component versions. The number of independent attestations is the <b>maximum independent set</b> of that correlation graph. In this example, thread-b and thread-c used the same toolchain, so three agreeing attestations count as two. That still meets the default k of two.",
    ], "left half first, from the outer box inwards; then the red box; then the nine rule chips and the three-node graph.", "namespaces, pivot_root, Landlock ABI, seccomp-BPF, user-notification supervisor, maximum independent set.")
    st += [PageBreak(), P("Live demonstration, part A", "h1"),
           P("Switch from the slides to the terminal and, side by side, the browser tab with the console (http://127.0.0.1:7790). Run one scenario at a time. "
             "Each one finishes in about 7 seconds and then holds; talk over the output, then press <b>Ctrl-C</b> before starting the next. "
             "Say this first: “Everything you are about to see is real: a mock AUR, the Warp log, three witnesses and three rebuilders, running as separate processes on this laptop. "
             "The ‘malicious’ packages are harmless probes that only read a planted decoy file and ping a local test server; nothing leaves the machine.”", "body")]
    st += SETUP
    st += demo_step("Scenario 1 — a healthy package: verify, don't build", "LOOM_HOLD=1 demo/run.sh healthy", [
        "Three rebuilders (thread-a, -b, -c) each print <i>reproducible</i> with the same short hash for libweft and hello-loom.",
        "<b>loom log</b>: tree size, the root hash, <i>cosigned by: witness-1, witness-2, witness-3</i>.",
        "<b>loom install hello-loom</b>: libweft is installed first (a dependency), both <b>ALLOWED</b>, <i>artifact … from peer http://127.0.0.1:773x</i>, and <i>post_install() ran under Heddle (full; exit 0; 0 denial(s))</i>.",
    ], [
        "“Three independent rebuilders reproduced these packages bit-for-bit and logged it. The log is cosigned by all three witnesses. Loom installed hello-loom by fetching the attested artifact from a peer by its hash, so <b>no PKGBUILD code ran on this machine</b>. Even the package's own install script ran inside the sandbox.”",
    ])
    st += demo_step("Scenario 2 — temporal quarantine and the advisory fast-path", "LOOM_HOLD=1 demo/run.sh quarantine", [
        "<b>fastmover 0.9-1 — BLOCKED (pre-build)</b>, [FAIL] temporal quarantine, <i>published 1h ago; quarantine is 3d — 2d 22h remaining</i>, and the exact override command.",
        "Then an advisory feed is loaded (CVE-2026-31337), and <b>tlsprobe 2.0.1-1 — ALLOWED</b>, although it is just as new.",
    ], [
        "“fastmover was published an hour ago, so it is held for 72 hours even though all three rebuilders reproduced it. Worms like Shai-Hulud spread within hours and are usually caught within days, so a short delay removes most of their reach. "
        "tlsprobe is just as new, but the Arch security advisory feed says it fixes a vulnerability, so the quarantine is waived. We don't want to delay security fixes.”",
    ])
    st += demo_step("Scenario 3 — the orphan-adoption attack", "LOOM_HOLD=1 demo/run.sh orphan", [
        "orphan-tool 1.0 by <b>bob</b> installs normally.",
        "<i>published orphan-tool 1.1-1 by mallory</i>; then all three rebuilders print <b>buildfailed … refused: build attempted openat /root/.curlrc [FR-3.2], socket … AF_INET [FR-3.4]</b>.",
        "<b>orphan-tool 1.1-1 — BLOCKED (pre-build)</b>: [FAIL] publishing-authority continuity, <i>maintainer changed: bob → mallory</i>, with dates and the source of the evidence.",
    ], [
        "“This models the 2026 AUR orphan-adoption waves. Bob abandoned the package; mallory adopted it and shipped 1.1. Loom remembers who published what you installed, notices the change of maintainer, and <b>blocks before building anything</b>.",
        "Independently, look at the rebuilders: 1.1's build tried to read a file in root's home and open an internet socket. Heddle denied both, and the rebuilders refused to vouch for it. That is two separate mechanisms catching the same attack.”",
    ])
    st += demo_step("Scenario 4 — build-time network injection (npm install inside a PKGBUILD)", "LOOM_HOLD=1 demo/run.sh npm", [
        "npm-helper 2.4 installs. carol's account is compromised and 2.5 is published.",
        "All three rebuilders: <b>buildfailed … refused: build attempted …</b>.",
        "<b>loom verify npm-helper --build</b> → <b>BLOCKED (pre-install)</b>, [FAIL] build confinement: <i>build tried to reach home/credential files and the network — contained by Heddle, artifact rejected (exit 0; 2 hostile access attempt(s))</i>, followed by the list of denials.",
        "<b>loom-testbed sink</b> → <i>(sink empty — no build reached the network)</i>.",
    ], [
        "“This is the Atomic Arch pattern: a package whose build quietly runs npm install to fetch a payload. Notice <b>exit 0</b>: the script swallowed its own errors so the build looks successful. Loom does not care. The build tried to use the network and read credentials, so it is hostile. And the test server, our sink, received nothing.”",
    ])
    st += demo_step("Scenario 7 — the sandbox contrast: same build, confined vs unconfined", "LOOM_HOLD=1 demo/run.sh sandbox", [
        "A decoy canary is planted in $HOME.",
        "(a) confined: <b>BLOCKED</b> with the two denials.",
        "(b) UNCONFINED (demo backend, clearly marked): <b>ALLOWED WITH WARNINGS</b> — <i>DEMO BACKEND: build ran WITHOUT kernel confinement</i>.",
        "<b>network sink hits: confined=0 unconfined=1</b> and <i>HIT … marker=loom-probe&amp;pkg=npm-helper&amp;stage=npm-install</i>.",
    ], [
        "“This is our headline empirical result. The <b>same</b> malicious build, run twice. Confined by Heddle, zero hits: it could not read the home directory or reach the network. Unconfined, the way a normal AUR helper runs it, it phoned home. We don't just claim the sandbox works; we show it denying the payload.”",
    ], "open the backup tab docs/demo-report.html and show the same result in the Heddle sandbox panel.")
    st += handoff("“That was containment and quarantine. [Presenter 4] will now show the attacks that try to hide: a rewritten history with a planted hook, a Python startup hook, and an attack on the log itself.” (Press Ctrl-C to stop the last scenario before handing over.)")
    st += qa([
        ("Why not simply use Docker or bubblewrap?", "Docker needs a root daemon and is built for isolation, not least-privilege policy; bubblewrap sets up namespaces but has no Landlock layer and does not explain denials. Heddle composes namespaces, Landlock and seccomp from a single declarative policy, so every denial names the requirement and rule that fired (FR-3.7), and it degrades to Landlock plus seccomp where user namespaces are disabled."),
        ("What is Landlock, and why is it important here?", "Landlock is a Linux security module (kernel 5.13+) that lets an unprivileged process restrict its own access to files; ABI 4 (kernel 6.7) adds TCP restrictions and ABI 6 (6.12) adds IPC scoping. It needs no root, so the sandbox still works in the reduced tier when namespaces are not allowed."),
        ("What is seccomp-BPF?", "A classic BPF program the kernel runs on every system call. It looks at the syscall number and arguments and returns allow, an error such as EPERM, or 'notify'. Loom returns EPERM for dangerous calls and, for socket and open calls, notifies a supervisor that logs and explains the denial. File access is always enforced by the namespace and Landlock, never by the supervisor alone, which avoids the known time-of-check-to-time-of-use race."),
        ("Why does clone3 return ENOSYS?", "seccomp can only inspect register arguments. clone3 passes its flags inside a struct in memory, so a filter cannot see whether it creates new namespaces. Returning 'not implemented' makes libc fall back to plain clone, whose flags are register arguments that the filter can check and refuse."),
        ("Why block the x32 ABI?", "x32 is an alternative system-call numbering on x86-64. If it were allowed, a program could reach a blocked system call through its x32 number and bypass the filter, so the filter rejects it (and kills on any foreign architecture)."),
        ("Won't the 'hostile denial' rule cause false positives?", "Only two kinds of denial count as hostile: reading home or credential paths (FR-3.2) and network use (FR-3.4). Undeclared reads and restricted syscalls are only logged, because normal toolchains trigger them. A package that genuinely needs the network at build time gets a recorded, audited exception (FR-3.8). Our false-positive test (E2) blocks 0 of 7 benign packages."),
        ("How is the number of independent rebuilders computed?", "As a maximum independent set on a graph where two attestations are connected if they share a rebuilder, an organisation or a toolchain ID. Up to 20 attestations we search exactly with bitmasks; above that a greedy bound is used that can only under-count, never over-count."),
        ("Why 72 hours of quarantine?", "It is the SRS default and it is configurable. Fast worms are usually detected and pulled within days, and genuine security fixes skip the wait through the advisory fast-path, so the cost to users is small."),
    ])
    st += numbers()
    return st


# =========================================================================== Presenter 4
def p4():
    st = header(4, "Live demo (part B), results & conclusion", "live scenarios 5, 6, 8 + full run; slides 13 – 16", "≈ 9 minutes (4 min demo, 5 min slides) + leading Q&A", "the jury (questions)", "Presenter 3 (demo part A)")
    st += [P("Live demonstration, part B", "h1"),
           P("You continue in the terminal. Same routine: run one scenario, talk over the output, then press <b>Ctrl-C</b>.", "body")]
    st += demo_step("Scenario 5 — force-push plus a planted pacman hook (defence in depth)", "LOOM_HOLD=1 demo/run.sh forcepush", [
        "forcepush-lib 3.1 installs. Then <i>published forcepush-lib 3.1-1-rewrite by frank (history rewritten)</i>.",
        "<b>BLOCKED (pre-build)</b>: [FAIL] continuity, <i>recipe history rewritten (force-push): commit … does not descend from it</i>.",
        "The user overrides the continuity alarm: <b>[OVRD]</b> continuity … <i>accepted by override #1</i>, and still <b>BLOCKED (pre-install)</b>: [FAIL] placement, <i>/usr/share/libalpm/hooks/zz-fp.hook — pacman hook: runs as root on every future package transaction</i>.",
    ], [
        "“This models the TeamPCP incident, where more than a hundred tags were force-pushed. Loom proves the new commit does not descend from the one you installed, using git's ancestry check, so the history was rewritten. Blocked.",
        "Now the interesting part: suppose the user reviews it and overrides that alarm. The package still carries a pacman hook, a file that would run as root on every future install. The <b>placement policy</b>, which looks at what a package installs, blocks it anyway. That is defence in depth, live.”",
    ])
    st += demo_step("Scenario 6 — a Python .pth startup hook (the LiteLLM vector)", "LOOM_HOLD=1 demo/run.sh placement", [
        "<b>pth-inject 1.0-1 — BLOCKED (pre-install)</b>: [FAIL] installed files do not create persistence or privilege, <i>…/site-packages/loomdemo.pth — .pth file with import lines: executes on every Python start (LiteLLM-style)</i>.",
    ], [
        "“A .pth file in site-packages runs on every Python start: a perfect persistence hook that no build sandbox can see, because nothing malicious happens at build time. That is how the LiteLLM compromise worked. Loom inspects the artifact's files before installing and blocks it.”",
    ])
    st += demo_step("Scenario 8 — a split-view attack on the log", "LOOM_HOLD=1 demo/run.sh splitview", [
        "Warp restarts in split-view mode with witness-3 corrupt. The victim syncs: size 6, cosigned by all three.",
        "The operator forks the victim's view; thread-a and thread-b attest a new hello-loom commit to the public log; the compromised thread-c's <b>backdoored</b> attestation goes only into the fork.",
        "<b>victim re-syncs:</b> <i>transparency log verification failed: checkpoint (size 7) carries 1 valid witness cosignature(s) [witness-3]; policy requires 2 of 3</i>.",
        "An uninvolved client still sees the honest history (size 8, all three witnesses).",
    ], [
        "“Now the attacker is the log operator itself, colluding with one compromised rebuilder and one corrupt witness. It shows the victim a private history containing a backdoored attestation. But the honest witnesses have already cosigned the public history, and a fork does not extend it, so they refuse. The victim's client sees only one cosignature where it needs two, and <b>rejects the fork</b>. Everyone else is unaffected.”",
    ])
    st += demo_step("Finale — the full run and the live console (optional, about 70 seconds)", "LOOM_HOLD=1 demo/run.sh", [
        "All nine scenarios stream past in the terminal. Switch to the browser tab <b>http://127.0.0.1:7790</b>.",
        "The console: service health (witness-3 turns red as corrupt in scenario 8), the log drawn as coloured threads, and the defence matrix filling in, with red cells spread across every column.",
    ], [
        "“This is our deployment console, reading the same services live. Watch the defence matrix: each red cell is a mechanism stopping a package, and the red is spread across every column. No single defence does all the work. At the end the run saves this page as a report file, so the result can be inspected afterwards.”",
    ], "if time is short, skip this and open docs/demo-report.html instead. It shows the same console from a completed run.")
    st += [P("Press Ctrl-C and return to the slides at slide 13.", "cue")]
    st += slide(13, "Results: every checked acceptance criterion passes", "1 min 30 s", [
        "Our specification defines six experiments. <b>E1</b>, attack replay: all nine malicious cases in our labelled incident corpus are blocked, and blocked <b>before any payload could run</b>. <b>E2</b>, false positives: none of the seven benign packages is blocked, even though they deliberately stress each mechanism, such as a fresh security release or a reviewed change of maintainer.",
        "<b>E3</b>, build compatibility, is a measurement rather than a pass or fail gate; the live demo measures it. <b>E4</b> is the chart: the ablation study. Detections are spread across five mechanisms, and the best single one catches only three of nine, so no single bypass defeats Loom.",
        "<b>E5</b>: a full policy decision takes 8.3 microseconds and verifying an Ed25519 attestation 60 microseconds in a release build, thousands of times under the targets, so installation time is dominated by the network. <b>E6</b>: 200 of 200 split views detected. And across the bottom, the sandbox contrast you saw live: zero hits confined, one unconfined.",
    ], "table, then chart, then the four tiles.")
    st += slide(14, "Live demonstration recap", "45 s", [
        "This table recaps what you just saw live, straight from the run's event journal. Rows are the nine scenarios and columns the mechanisms. Red cells show where a mechanism stopped a package. They appear in every column, so the ablation result also holds on the live system. Scenario 8's only red cell is the witnesses column: the fork was rejected.",
    ])
    st += slide(15, "Conclusion", "1 min 30 s", [
        "To conclude: Loom turns installing community software into a verifiable decision instead of an act of faith. It <b>contains</b> every build, <b>verifies</b> artifacts through independent rebuilders and a witnessed log, <b>detects</b> changes of authority, fresh releases and persistence hooks, and <b>explains</b> every decision.",
        "We are candid about the limitations. Rebuilder independence is simulated on one machine; a real deployment needs independent operators. Attestation proves that an artifact matches its source, not that the source is benign. And admission to the log is permissioned. Future work follows from these: a real federation of rebuilders and witnesses; npm, PyPI and crates.io backends, which the engines already support unchanged; a peer-to-peer transport; and formal verification of the policy engine.",
        "Thank you. We are happy to take your questions.",
    ])
    st += slide(16, "References", "leave on screen", [
        "(Do not read. Leave this slide up during questions. If asked about a source, the numbers match the literature review slides.)",
    ])
    st += [Spacer(1, 6), boxed([P("<b>Leading the Q&amp;A</b>", "h3"),
                                P("Repeat each question briefly so everyone hears it, then route it: motivation and literature → Presenter 1; architecture and cryptography → Presenter 2; sandbox and policy → Presenter 3; demo, results and limitations → you.", "say")], AMBERSOFT, AMBER)]
    st += qa([
        ("Is the evaluation realistic? You built the corpus yourselves.", "The corpus models the real 2024–2026 incident classes (orphan adoption, force-push, build-time injection, credential theft, worms, tampered artifacts, fresh malicious releases, pacman hooks and .pth hooks). The live fixtures are harmless probes that behave like those payloads. We acknowledge that a larger, independent corpus is future work, and E2 guards against over-fitting with deliberately tricky benign cases."),
        ("What happens to packages that are not reproducible?", "They never reach k attestations. By default (on_insufficient_attestations = warn) Loom then builds locally inside Heddle and warns; a stricter policy can block instead. Non-reproducibility is also measured and classified (E3)."),
        ("Are the performance numbers from a debug or release build?", "Release: 8.3 µs per decision and 60 µs per Ed25519 verification, averaged over 2,000 iterations. The debug build is slower (about 9 ms per verification) but still well under the 100 ms target."),
        ("Would Loom have stopped the XZ Utils backdoor?", "Honestly, not on its own. XZ's payload was in the published source tarball, so every honest rebuilder would reproduce it; that is our stated out-of-scope case OOS-5. What Loom adds is the witnessed log and the audit: once the backdoor is discovered, one revocation reaches every client, and <i>loom audit</i> shows exactly which machines installed it. The sandbox would also have stopped any build-time credential theft."),
        ("Doesn't failing closed make Loom annoying to use?", "Every block states the rule, the evidence and the exact command to proceed (NFR-USE-2). Overrides are explicit, recorded and listed by loom audit, so the user stays in control and nothing is silently weakened."),
        ("What would a real deployment need?", "Independent organisations running rebuilders with diverse toolchains, several independent witnesses, an admission policy for rebuilders, and a peer-to-peer transport. The protocol and threshold logic are already real; only the deployment is simulated."),
        ("Why is the demo on loopback? Is it really distributed?", "Every component is a separate process talking over HTTP with its own keys: the mock AUR, the log, three witnesses, three rebuilders and three peers. Loopback just keeps the demo self-contained and safe; the same binaries run across machines by changing the addresses in the configuration."),
    ])
    st += numbers()
    return st


for n, fn, fname in [(1, p1, "Presenter1_Introduction_and_Research.pdf"), (2, p2, "Presenter2_Architecture_and_Cryptography.pdf"),
                     (3, p3, "Presenter3_Sandbox_Policy_and_Demo_A.pdf"), (4, p4, "Presenter4_Demo_B_Results_and_Conclusion.pdf")]:
    build(os.path.join(OUT, fname), fn(), f"Loom — Major Project Review · Speaker script · Presenter {n}")
    print("wrote", fname)
