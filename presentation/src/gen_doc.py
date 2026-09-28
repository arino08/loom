"""Loom — technical design and security report (PDF)."""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from pdfkit import *  # noqa
from reportlab.platypus import Image as RLImage

HERE = os.path.dirname(__file__)
OUT = "/home/user/loom/presentation/Loom_Technical_Design_and_Security_Report.pdf"
refs = json.load(open(os.path.join(HERE, "refs.json")))
W = 174 * mm
st = []
fig_no = [0]
tab_no = [0]


def H1(t): st.append(CondPageBreak(40 * mm)); st.append(P(t, "h1"))
def H2(t): st.append(CondPageBreak(30 * mm)); st.append(P(t, "h2"))
def H3(t): st.append(P(t, "h3"))
def B(t): st.append(P(t, "body"))
def L(items): st.extend(bullets(items))
def C(t): st.append(code(t)); st.append(Spacer(1, 6))
def T(rows, widths, caption=None):
    if caption:
        tab_no[0] += 1
        st.append(P(f"<b>Table {tab_no[0]}.</b> {caption}", "small"))
        st.append(Spacer(1, 2))
    st.append(table(rows, widths)); st.append(Spacer(1, 8))
def FIG(name, caption, w=W):
    fig_no[0] += 1
    from PIL import Image as PI
    fp = os.path.join(HERE, "fig", name + "-c.png"); iw, ih = PI.open(fp).size
    img = RLImage(fp, width=w, height=w * ih / iw)
    img.hAlign = "CENTER"
    st.append(KeepTogether([img, P(f"<b>Fig. {fig_no[0]}.</b> {caption}", "small"), Spacer(1, 8)]))
def NOTE(t, bg=AMBERSOFT, border=AMBER): st.append(boxed([P(t, "body")], bg, border)); st.append(Spacer(1, 8))


# ------------------------------------------------------------------ title page
st += [Spacer(1, 30 * mm), P("GROUP NO. 14 · MAJOR PROJECT · TECHNICAL REPORT", "eyebrow"),
       P("Loom: A Decentralised, Verifying Package Manager for the Arch User Repository", "title"),
       P("Technical design and security report: how every part works, and why it is secure", "subtitle"), Spacer(1, 10)]
st.append(table([["Team member", "Roll No."], ["Aiman Haque", "231415"], ["Zoya Mulani", "231453"], ["Aariz Sheikh", "231453"], ["Yusuf Aslam", "231460"]], [90 * mm, 40 * mm]))
st += [Spacer(1, 8), P("Guide: [Guide Name] · Department of [Department] · [Institution] · September 2026", "body"), Spacer(1, 14)]
st.append(boxed([P("<b>Abstract</b>", "h3"), P(
    "Community package repositories such as the Arch User Repository (AUR) execute unreviewed build scripts with the user's full privileges and install whatever a maintainer publishes. "
    "Loom is a client-side package manager that installs AUR packages only under an enforceable trust policy, without requiring any cooperation from the AUR, its maintainers or upstream projects. "
    "It combines five independent mechanisms: a least-privilege build sandbox (Heddle); k-of-n independent, reproducible-build attestations (Thread and Weave); temporal quarantine; publishing-authority continuity checks; and a witness-cosigned Merkle transparency log (Warp). "
    "This report explains how each mechanism works and which attacks it defeats, with particular attention to the cryptography (SHA-256, Ed25519, DSSE, canonical JSON, RFC 6962 Merkle trees, signed notes and witness cosignatures) and to the Linux kernel isolation primitives (namespaces, Landlock and seccomp-BPF). "
    "On a labelled incident corpus Loom blocks 9 of 9 malicious cases with 0 of 7 false positives, detects 200 of 200 split-view attacks, and decides in microseconds.", "body")], SOFT))
st.append(PageBreak())

# ------------------------------------------------------------------ contents
st.append(P("Contents", "h1"))
toc = ["1. The problem: why installing from the AUR is dangerous", "2. Threat model", "3. System overview", "4. How an install works, end to end",
       "5. Cryptographic foundations", "6. The Warp transparency log", "7. Heddle: the build sandbox", "8. Thread: independent rebuilders",
       "9. Weave: the policy engine", "10. Shuttle: content-addressed distribution", "11. How each attack is defeated", "12. Evaluation",
       "13. Limitations and future work", "14. Glossary", "References"]
L(toc)
st.append(PageBreak())

# ------------------------------------------------------------------ 1
H1("1. The problem: why installing from the AUR is dangerous")
B("The Arch User Repository is a community collection of <i>recipes</i> (PKGBUILD shell scripts) rather than pre-built packages. An AUR helper such as yay or paru downloads a recipe and runs <font name='Mono'>makepkg</font>, which executes the PKGBUILD's functions (<font name='Mono'>prepare()</font>, <font name='Mono'>build()</font>, <font name='Mono'>package()</font>) <b>as the invoking user</b>, with full access to that user's home directory, credentials and network. pacman then installs the result as root and runs the package's <font name='Mono'>.INSTALL</font> scriptlet as root.")
B("Four properties of this model make it attractive to attackers:")
L(["<b>No review and no signing.</b> Any account can upload a recipe, and nothing binds a published recipe or artifact to a verified identity.",
   "<b>Orphan adoption.</b> When a maintainer disowns a package, any user may adopt it and push new versions to every existing user. Abandonment is common and users rarely plan for it [6].",
   "<b>Code runs before anything is checked.</b> The build script is itself the payload carrier. Studies of malicious packages find that most reach victims through source installation (74.81% in PyPI [3]) and that credential theft and command execution dominate [3], [4].",
   "<b>Persistence outlives the build.</b> A package can install files that execute later with high privilege, for example pacman hooks (run as root on every transaction), <font name='Mono'>/etc/ld.so.preload</font>, or Python <font name='Mono'>.pth</font> files (run on every interpreter start)."])
B("The research literature frames the space: a taxonomy of 107 attack vectors linked to 94 real incidents [1]; datasets of tens of thousands of malicious packages [4]; the XZ Utils backdoor (CVE-2024-3094), which combined a patient maintainer takeover with a payload hidden in the build process [5]. "
  "Existing defences cover parts of the problem: malware detectors are probabilistic [2]; signing needs registry cooperation and proves <i>who</i> published, not <i>what</i> [7], [8]; reproducible-builds research measures reproducibility but does not turn it into an install decision [11], [12]; and fewer than 1% of packages sandbox themselves [15].")
NOTE("<b>Design stance.</b> Loom is a trust-and-containment system, not a malware scanner. It never tries to decide whether code is malicious. Instead it (a) confines what any build can do, (b) requires independent, publicly logged evidence that an artifact corresponds to its source, and (c) notices changes in who controls a package, and it does all of this without cooperation from anyone upstream.")

# ------------------------------------------------------------------ 2
H1("2. Threat model")
B("The threat model follows the project's Software Requirements Specification (LOOM-SRS-001). The adversary may do any of the following:")
T([["ID", "Adversary capability", "Primary Loom defence"],
   ["ADV-1", "Compromise a maintainer's account or token (including by changing its e-mail)", "Continuity, quarantine, sandbox"],
   ["ADV-2", "Adopt an orphaned package through the legitimate process", "Continuity (maintainer change)"],
   ["ADV-3", "Compromise CI/CD or reuse a rotated token", "k-of-n reproducible rebuilds"],
   ["ADV-4", "Publish a correctly signed artifact that does not correspond to its source", "Rebuilds + contradiction rule"],
   ["ADV-5", "Execute code at build or install time and exfiltrate credentials", "Heddle sandbox, install scripts in sandbox"],
   ["ADV-6", "Self-propagate using harvested credentials (worm)", "Heddle (no credentials reachable), quarantine"],
   ["ADV-7", "Act as a network adversary on the peer-to-peer layer", "Content addressing (SHA-256)"],
   ["ADV-8", "Operate a minority (&lt; k) of rebuilders or witnesses", "Thresholds, independence counting"],
   ["ADV-9", "Present divergent log histories to different clients (split view)", "Witness cosigning, client cross-checks"]],
  [16 * mm, 98 * mm, 60 * mm], "In-scope adversary capabilities (SRS §4).")
B("Explicitly <b>out of scope</b>: ≥ k organisationally distinct rebuilders compromised at once (OOS-1); breaking SHA-256 or Ed25519 (OOS-2); a kernel or LSM escape on a correctly configured host (OOS-3); compromise of the Loom binary before installation (OOS-4); malicious source code that every rebuilder faithfully reproduces (OOS-5), because attestation proves correspondence, not benignity; and a shared compromised compiler, the Thompson attack (OOS-6), which toolchain diversity mitigates but does not eliminate. "
  "Assumptions include that the AUR is readable unauthenticated and that the host kernel is not already compromised.")

# ------------------------------------------------------------------ 3
H1("3. System overview")
B("Loom is a Rust workspace of eleven crates (about 12,700 lines, 75 automated tests). The client runs on the user's machine; the rebuilders, witnesses and log are independent services. In the prototype all of them run as separate processes on loopback, and rebuilder independence is simulated with deliberately different toolchain descriptors (SRS ASM-4). The protocols and thresholds are real.")
FIG("architecture", "System architecture. Everything that crosses into the client (dashed box) is verified by a hash or a signature before use; any failure refuses (fail closed).")
T([["Subsystem", "Role", "Key technique"],
   ["Heddle", "Runs every build step and install script under least privilege", "User/mount/net/PID/IPC/UTS/cgroup namespaces, pivot_root tmpfs, Landlock, seccomp-BPF + supervisor"],
   ["Thread", "Rebuilder daemon: builds each package twice and signs an attestation", "reprotest-style variation, in-toto statement in a DSSE envelope, Ed25519"],
   ["Warp", "Append-only transparency log of attestations and revocations", "RFC 6962 Merkle tree, C2SP signed-note checkpoints, witness cosignatures"],
   ["Weave", "Pure policy function: evidence → explained decision", "k-of-n via maximum independent set, contradiction, quarantine, continuity, placement"],
   ["Shuttle", "Fetches artifacts from peers by content address", "SHA-256 verification; peers provide availability, never integrity"],
   ["AUR backend", "The only AUR-aware code (behind the ecosystem Backend trait)", ".SRCINFO parsing (never sourcing PKGBUILD), git, libalpm vercmp port"]],
  [22 * mm, 66 * mm, 86 * mm], "Subsystems.")
B("<b>Layering (NFR-MNT-1).</b> <font name='Mono'>loom-core</font> holds all shared, AUR-agnostic types (digests, canonical JSON, DSSE, keys, attestation schema). The engines (<font name='Mono'>loom-warp</font>, <font name='Mono'>loom-heddle</font>, <font name='Mono'>loom-shuttle</font>, <font name='Mono'>loom-weave</font>) must never depend on <font name='Mono'>loom-aur</font>; all ecosystem knowledge sits behind <font name='Mono'>loom_core::ecosystem::Backend</font>. An npm, PyPI or crates.io backend therefore needs no change to any security engine.")

# ------------------------------------------------------------------ 4
H1("4. How an install works, end to end")
FIG("install-flow", "The install pipeline. Steps 1–4 execute no package code. When k independent rebuilders agree, the artifact is fetched by hash and the PKGBUILD never runs on the user's machine.")
L(["<b>1. Resolve.</b> Query the AUR RPC for the package and its transitive AUR dependencies (official-repository dependencies are delegated to pacman, FR-1.4). Dependencies are processed first.",
   "<b>2. Fetch the recipe.</b> Clone the package's git repository and parse <font name='Mono'>.SRCINFO</font> to learn the version, sources and checksums. The PKGBUILD is never sourced to read metadata (FR-3.9). Record the maintainer, HEAD commit and upstream signing keys (<font name='Mono'>validpgpkeys</font>).",
   "<b>3. Gather evidence.</b> Update and verify the transparency log (Section 6); collect and verify every attestation and revocation for the package; compute continuity against the local baseline and against the log's own history; check the quarantine window and the advisory feed.",
   "<b>4. Evaluate.</b> Weave evaluates all rules (Section 9). A block is final at this point: the user sees the rule, the evidence and the remediation, and no package code has run (AC-1: blocked before payload).",
   "<b>5. Obtain the artifact.</b> Prefer the attested artifact, fetched from Shuttle peers by its SHA-256 digest (<i>verify, don't build</i>). Only if no peer serves it, build locally inside Heddle.",
   "<b>6. Inspect.</b> List the artifact's files and apply the placement policy; strip the <font name='Mono'>.INSTALL</font> scriptlet so pacman can never run it unconfined.",
   "<b>7. Re-evaluate</b> with the concrete candidate digest, local build report and placement findings; any of these can still block.",
   "<b>8. Install</b> via <font name='Mono'>pacman -U</font> (or extract-into-root in the demo), run install scripts under Heddle per policy, and record the continuity baseline and install database."])
FIG("sequence-flow", "Where the evidence comes from: rebuild, attest, log, witness, verify.")

# ------------------------------------------------------------------ 5
H1("5. Cryptographic foundations")
B("Constraint CON-5 forbids bespoke cryptography. Loom uses exactly two audited primitives, from two audited libraries: <b>SHA-256</b> (the <font name='Mono'>sha2</font> crate) and <b>Ed25519</b> (<font name='Mono'>ed25519-dalek</font> 2.1). The log's Merkle hashing and note framing come from <font name='Mono'>tlog_tiles</font> and <font name='Mono'>signed_note</font>, Rust ports of Go's audited sumdb/tlog and note packages. Everything else in this section is a way of arranging these two primitives so that the right thing gets signed.")

H2("5.1 SHA-256: content addressing and hashing")
B("SHA-256 (FIPS 180-4) is a Merkle–Damgård hash function. The message is padded (a 1 bit, zeros, then the 64-bit message length) to a multiple of 512 bits and processed block by block. Each block is expanded into a 64-word message schedule and mixed into eight 32-bit state words over 64 rounds of additions, rotations and the Ch/Maj/Σ functions, with round constants derived from the cube roots of the first 64 primes. The final state is the 256-bit digest.")
T([["Property", "Meaning", "Best known generic attack cost"],
   ["Pre-image resistance", "Given a digest, find any input with that digest", "≈ 2<super>256</super>"],
   ["Second pre-image resistance", "Given an input, find a different input with the same digest", "≈ 2<super>256</super>"],
   ["Collision resistance", "Find any two inputs with the same digest", "≈ 2<super>128</super> (birthday bound)"]],
  [44 * mm, 80 * mm, 50 * mm], "Security properties of SHA-256 that Loom relies on.")
B("<b>How Loom uses it.</b> Every artifact is identified by <font name='Mono'>sha256:&lt;64 hex digits&gt;</font> (FR-2.1). Collision resistance is what makes <i>content addressing</i> safe: a peer cannot serve different bytes under the same name, so data from untrusted peers is trusted only after its digest matches the one in the witness-cosigned attestations (FR-2.6). SHA-256 also produces the <i>source digest</i> of the prepared build inputs, key IDs (the first 16 hex digits of SHA-256 over the public key, e.g. <font name='Mono'>ed25519:3f9a…</font>), the <i>toolchain ID</i> (SHA-256 over the canonical JSON of the build image and component versions, used to judge independence), and every node of the Merkle tree. Length-extension attacks do not apply because Loom never uses SHA-256 as a MAC.")

H2("5.2 Ed25519: digital signatures")
B("Ed25519 (RFC 8032) is the Edwards-curve Digital Signature Algorithm over the twisted Edwards curve <i>−x² + y² = 1 + d·x²·y²</i> over the prime field GF(p) with p = 2<super>255</super> − 19 (birationally equivalent to Curve25519). The base point B generates a subgroup of prime order ℓ = 2<super>252</super> + 27742317777372353535851937790883648493, and the curve has cofactor 8. Security is about 128 bits: the best known attack, Pollard's rho, needs roughly √ℓ ≈ 2<super>126</super> group operations.")
C("Key generation   seed k ← 32 random bytes (OS CSPRNG)\n                 h = SHA-512(k);  a = clamp(h[0..32]);  prefix = h[32..64]\n                 A = a·B          public key = encode(A)  (32 bytes)\n\nSign(M)          r = SHA-512(prefix ‖ M) mod L        (deterministic nonce)\n                 R = r·B\n                 c = SHA-512(encode(R) ‖ encode(A) ‖ M) mod L\n                 S = (r + c·a) mod L                  signature = R ‖ S  (64 bytes)\n\nVerify(M, R‖S)   reject if S ≥ L, or A / R is not a valid (strict) encoding\n                 c = SHA-512(R ‖ A ‖ M) mod L\n                 accept iff  S·B = R + c·A")
B("<b>Why Ed25519.</b> (1) <b>Deterministic nonces:</b> r is derived from the key and message, so a weak random number generator at signing time cannot leak the private key, the failure that has broken ECDSA deployments. (2) Small keys and signatures (32 and 64 bytes) and fast verification: about <b>60 µs</b> per attestation in our release-build benchmark. (3) Standardised and widely audited.")
B("<b>verify_strict.</b> Loom verifies with <font name='Mono'>verify_strict</font>, which rejects non-canonical S values and small-order points for A and R. That removes signature malleability and weak-key edge cases, so a signature is valid under exactly one interpretation.")
B("<b>Key management.</b> Each rebuilder, the log, each witness and the revocation authority has its own key (FR-4.3). Private keys are written with file mode 0600 and read only by the owning process; there is no API that sends a private key over the network (NFR-SEC-2). Clients are configured with the <i>public</i> keys they trust, and a signature is accepted only from a key the caller explicitly passes in (FR-2.6).")

H2("5.3 Canonical JSON: deterministic bytes")
B("A signature covers bytes, not meaning. If two serialisers produced different bytes for the same record, an honest record could fail verification, or a client could not recompute what a log stored. Loom serialises every signed record with a subset of RFC 8785 (JCS): object keys sorted by code point, no insignificant whitespace, and <b>no floating-point numbers</b> (rejected outright, since float formatting is where serialisers differ). The log re-canonicalises what it stores, so any client recomputes byte-identical leaves.")
C('input:     {"b": 1, "a": {"z": [1, 2], "y": "s"}}\ncanonical: {"a":{"y":"s","z":[1,2]},"b":1}')

H2("5.4 DSSE envelopes and in-toto statements")
B("Attestations and revocations are in-toto v1 <i>Statements</i> wrapped in a DSSE (Dead Simple Signing Envelope), the format used by in-toto and Sigstore. The signature does not cover the raw JSON. It covers the <b>Pre-Authentication Encoding</b>:")
C('PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body\n\ntype = "application/vnd.in-toto+json"\nsig  = Ed25519.Sign(sk, PAE(type, body))\nenvelope = { payloadType: type,\n             payload:     base64(body),\n             signatures:  [ { keyid, sig: base64(sig) } ] }')
B("Length-prefixing makes the encoding unambiguous: no choice of type and body can be split differently to produce the same signed bytes, so nothing can be spliced between messages. Inside the body, the statement's <font name='Mono'>predicateType</font> distinguishes a rebuild attestation (<font name='Mono'>https://loom.dev/attestation/rebuild/v1</font>) from a revocation (<font name='Mono'>…/revocation/v1</font>). Because it is part of the signed body and checked on decode, a signature over an attestation can never be reused as a revocation.")
T([["Field of the rebuild predicate", "What it binds"],
   ["package, version, ecosystem", "which package the claim is about"],
   ["source.repo, source.commit, source.digest", "exactly what was built: the recipe commit and the SHA-256 of all prepared inputs"],
   ["outcome", "reproducible | unreproducible | build_failed"],
   ["artifact, variant_digests", "the artifact digest (present only if reproducible) and each variant build's digest"],
   ["rebuilder.id, rebuilder.org", "who built it: the basis of organisational independence"],
   ["toolchain.id, image, components, sandbox_tier", "how it was built: the basis of toolchain independence (FR-4.5)"],
   ["observed.maintainer, observed.last_modified", "what the AUR said at build time: continuity evidence from the log's history"],
   ["timestamp, disputes", "when; and other digests for the same source that this rebuilder disagrees with (negative attestation, FR-4.6)"]],
  [62 * mm, 112 * mm], "The signed rebuild predicate.")
B("A <b>revocation</b> names the leaf it revokes by index <i>and</i> by the SHA-256 of the leaf bytes, plus a reason and the revoker. A rebuilder may revoke only its own attestations; a configured revocation authority may revoke any. Revocations invalidate an attestation without removing it from history (FR-5.8), and every client applies all revocations before deciding (FR-5.9).")

# ------------------------------------------------------------------ 6
H1("6. The Warp transparency log")
FIG("crypto-warp", "The cryptographic building blocks and an inclusion proof in an 8-leaf Merkle tree.")
H2("6.1 Merkle tree hashing (RFC 6962 / RFC 9162)")
B("Warp stores every accepted record as a leaf of an append-only Merkle tree. The tree hash of n leaves D[0..n) is defined recursively, with <b>domain separation</b> between leaves and interior nodes:")
C("MTH({})        = SHA-256()                          (empty tree)\nMTH({d})       = SHA-256(0x00 ‖ d)                  (leaf hash)\nMTH(D[0..n))   = SHA-256(0x01 ‖ MTH(D[0..k)) ‖ MTH(D[k..n)))\n                 where k is the largest power of two strictly less than n")
B("The 0x00/0x01 prefixes prevent a <b>second-pre-image attack on the tree</b>: without them an attacker could present the concatenation of two child hashes as if it were a leaf and prove the 'inclusion' of a record that was never logged.")
H2("6.2 Inclusion proofs")
B("To prove that leaf m is in a tree of size n, the log returns the <i>audit path</i>: the sibling hash at each level from the leaf up to the root, which is ⌈log₂ n⌉ hashes. The verifier recomputes the root from the leaf hash and the path and compares it with the root in a trusted checkpoint. In Fig. 4, proving d2 needs only three hashes (d3, h1.0 and h2.1). For a log of one million records a proof has 20 hashes, about 640 bytes.")
C("h  = SHA-256(0x00 ‖ d2)\nh  = SHA-256(0x01 ‖ h ‖ H(d3))        # d2 is a left child\nh  = SHA-256(0x01 ‖ h1.0 ‖ h)         # h1.1 is a right child\nh  = SHA-256(0x01 ‖ h ‖ h2.1)         # h2.0 is a left child\naccept iff h == root in the cosigned checkpoint")
H2("6.3 Consistency proofs and append-only history")
B("A consistency proof shows that the tree of size n is an extension of the tree of size m &lt; n: the first m leaves are unchanged. It consists of the O(log n) subtree hashes that let a verifier compute both the old root and the new root. A client that saved a checkpoint of size m verifies consistency before accepting size n (FR-5.7); a log that rewrote or removed any earlier record cannot produce a valid proof. Removing a record, or quietly hiding a revocation, therefore becomes detectable.")
H2("6.4 Checkpoints (signed tree heads)")
B("After every append, Warp signs a <b>checkpoint</b> in the C2SP tlog-checkpoint format, wrapped in a C2SP signed note:")
C("demo.loom/warp                                   ← origin (log identity)\n35                                               ← tree size\nS3grCwYxvQRG7Kz30Bo4g8H4RO6C+ETLZ305tw6pwgk=     ← base64 root hash\n\n— demo.loom/warp  base64( keyID[4] ‖ Ed25519 signature[64] )\n— witness-1       base64( keyID[4] ‖ u64be(timestamp) ‖ signature[64] )\n— witness-2       …")
B("A key ID is the first four bytes of SHA-256(name ‖ 0x0A ‖ algorithm byte ‖ public key). The log signs with algorithm byte <b>0x01</b> (Ed25519). Witnesses sign with <b>0x04</b> (cosignature/v1), and their signed message is different: <font name='Mono'>\"cosignature/v1\\ntime &lt;ts&gt;\\n\" ‖ checkpoint body</font>. So a witness key can never be mistaken for a log key, and a cosignature can never be replayed as a log signature.")
H2("6.5 Witnesses and the split-view attack")
B("A malicious log operator could keep two histories and show a <i>victim</i> a private fork, for example one containing a backdoored attestation, while showing everyone else the honest log. This is a <b>split view</b> (ADV-9). It is defeated by <b>witnesses</b> implementing C2SP tlog-witness:")
L(["The log sends each witness the new checkpoint together with a consistency proof from the size that witness last cosigned.",
   "The witness verifies the log's signature and the consistency proof. If the new tree does not extend the old one it refuses (HTTP 409 with its current size). Otherwise it cosigns and persists the new size and root.",
   "An honest witness therefore vouches for <b>at most one linear history</b>."])
B("<b>Quorum arithmetic.</b> Let n be the number of witnesses and t the number of cosignatures a client requires. Two quorums of size t must share at least 2t − n witnesses. A split view needs both histories to reach quorum, so it is <b>prevented</b> as long as fewer than 2t − n witnesses collude. With Loom's default t = 2, n = 3, any two quorums share at least one witness, so a split view is impossible while at most one witness is corrupt. Beyond prevention, the client <b>detects</b> split views by cross-checking each witness's latest cosigned checkpoint against its own view.")
H2("6.6 Client verification algorithm (fail closed)")
L(["1. Fetch the checkpoint; verify the log's Ed25519 signature against the configured log key.",
   "2. Count valid cosignatures from configured witnesses; require ≥ witness_threshold (FR-5.6).",
   "3. Verify a consistency proof from the persisted head; refuse on any inconsistency (FR-5.7), then persist the new head.",
   "4. Cross-check each witness's own latest checkpoint. If two log-signed checkpoints are mutually inconsistent, save both: they are transferable proof of misbehaviour.",
   "5. Mirror every record and recompute the root locally, so the log cannot hide records (in particular revocations). Verify inclusion of every attestation used (FR-5.5).",
   "Any failure yields a refusal, never a silent fallback to unverified data (NFR-SEC-1). An unreachable log is reported as <i>unavailable</i> and handled by policy (NFR-REL-2)."])
B("<b>Admission.</b> Warp accepts a record only if it is signed by a configured rebuilder key whose id matches the rebuilder named inside the statement, or by a revocation authority. Permissionless admission is deliberately deferred (Sybil resistance is an open problem; SRS Appendix C).")
NOTE("<b>Live evidence (demo scenario 8).</b> Warp is restarted in split-view mode with witness-3 corrupted. The operator forks the victim's view and, colluding with a compromised rebuilder, appends a backdoored attestation only to the fork. The honest witnesses have already cosigned the public history, which the fork does not extend, so they refuse. The victim's client reports: <i>checkpoint (size 7) carries 1 valid witness cosignature(s) [witness-3]; policy requires 2 of 3</i>, and rejects it. Other clients keep the honest size-8 history.", GREENSOFT, GREEN)

# ------------------------------------------------------------------ 7
H1("7. Heddle: the build sandbox")
FIG("heddle-weave", "Heddle's three nested layers (left) and Weave's rule chain and independence graph (right).")
B("Every build step and install scriptlet runs under Heddle. One declarative access policy (read-only toolchain paths, a writable build directory, no network) is compiled into three independent enforcement layers, so a denial always names the requirement and rule the kernel actually enforced (FR-3.7).")
H2("7.1 Layer 1: Linux namespaces")
T([["Namespace", "Effect inside the sandbox"],
   ["user", "The build runs as an unprivileged user mapped into a private user namespace; it can create the other namespaces without real root."],
   ["mount", "A fresh tmpfs becomes the root via pivot_root, and the old root is detached. It contains only read-only binds of /usr, /bin, /lib, /opt, a curated subset of /etc (not the pacman keyring, host SSH keys, sudoers or network credentials), a minimal /dev, a private /proc and /tmp, and the build directory at /build. $HOME, /root, /run and /var do not exist."],
   ["network", "An empty network namespace: no interfaces except loopback, so no route out (FR-3.4)."],
   ["PID", "The build cannot see or signal host processes; when the build ends, the namespace and a process-group SIGKILL guarantee nothing survives (NFR-REL-3)."],
   ["IPC, UTS, cgroup", "No shared memory or message queues with the host; private hostname; private cgroup view."]],
  [26 * mm, 148 * mm], "Namespaces used in the full tier.")
H2("7.2 Layer 2: Landlock")
B("Landlock is a Linux security module (kernel ≥ 5.13) that lets an <b>unprivileged</b> process restrict itself irrevocably. Heddle requests up to ABI v6: read and execute beneath the toolchain paths; full access beneath the build directory and /tmp; TCP bind/connect handling (ABI 4, kernel 6.7) so no TCP is allowed; and scoping of abstract UNIX sockets and signals (ABI 6, kernel 6.12). On older kernels it applies what is available and reports reduced assurance. Landlock is defence in depth in the full tier and the <i>only</i> filesystem enforcement in the reduced tier; if Landlock is unavailable, the build is refused.")
H2("7.3 Layer 3: seccomp-BPF with a supervisor")
B("seccomp-BPF attaches a classic BPF program that the kernel runs on every system call. Heddle's filter is hand-assembled (small enough to audit):")
C("load arch;     if arch != AUDIT_ARCH_X86_64/AARCH64 → KILL_PROCESS\nload nr;       if nr ≥ 0x40000000 (x32 ABI)           → EPERM\n               if nr ∈ {ptrace, mount, umount2, pivot_root, unshare, setns, bpf,\n                        io_uring_*, kexec_*, *_module, keyctl, add_key, userfaultfd,\n                        perf_event_open, open_by_handle_at, fsopen/fsmount/move_mount,\n                        process_vm_readv/writev, swapon, reboot, seccomp, …} → EPERM\n               if nr == clone3                        → ENOSYS\n               if nr == clone and flags ∩ CLONE_NEW*  → EPERM\n               if nr == socket and family != AF_UNIX  → NOTIFY (supervisor)\n               if nr ∈ {openat, openat2, execve, mkdirat, unlinkat, rename, …} → NOTIFY\n               otherwise                              → ALLOW")
L(["<b>x32 blocking.</b> x32 is an alternative syscall numbering on x86-64. If it were allowed, a program could reach a blocked system call through its x32 number and bypass the filter.",
   "<b>io_uring</b> is refused because operations submitted through its rings do not pass through seccomp at all.",
   "<b>clone3 → ENOSYS.</b> seccomp inspects only register arguments; clone3 passes its flags inside a struct in memory, so the filter could not see namespace flags. 'Not implemented' makes libc fall back to clone, whose flags are registers and are checked.",
   "<b>Supervisor (SECCOMP_RET_USER_NOTIF).</b> Socket and path-opening calls are forwarded to a supervisor process, which classifies the resource against the policy, logs a denial with the rule and requirement (for example <i>openat /root/.curlrc [deny-home-and-credentials FR-3.2]</i>), and answers EACCES; otherwise it lets the kernel decide (SECCOMP_USER_NOTIF_FLAG_CONTINUE)."])
NOTE("<b>No TOCTOU weakness.</b> User-notification supervisors have a known time-of-check-to-time-of-use race (the process can change a path after the supervisor reads it). Heddle never relies on the supervisor for enforcement: files are enforced by the mount namespace and Landlock, and the supervisor only explains and denies early what those layers would deny anyway.")
H2("7.4 Tiers, fail-closed behaviour and hostile denials")
T([["Tier", "When", "Enforcement"],
   ["full", "Unprivileged user namespaces available", "All namespaces + Landlock + seccomp"],
   ["reduced", "User namespaces disabled on the host", "Landlock + seccomp; reported as reduced assurance (NFR-MNT-3)"],
   ["refused", "No Landlock at all", "The build is refused; never run unconfined (NFR-SEC-1)"]],
  [22 * mm, 64 * mm, 88 * mm], "Sandbox tiers.")
B("<b>Hostile denials.</b> A payload can wrap itself in <font name='Mono'>|| true</font> so that the build still exits 0 after the sandbox denies it. Loom therefore classifies two kinds of denial as evidence of hostile intent: any read of home or credential paths (FR-3.2) and any network socket (FR-3.4) unless a recorded, per-package network exception exists (FR-3.8). A rebuilder that sees such a denial <b>refuses to attest</b> (outcome build_failed, no artifact claim), and Weave <b>fails the sandbox rule</b> for a local build, whatever the exit status. Undeclared reads (FR-3.1) and restricted syscalls (FR-3.6) are only logged, because benign toolchains trigger them.")
B("<b>Install scripts.</b> The artifact given to pacman has its .INSTALL removed, and Loom runs install scriptlets itself under Heddle according to <font name='Mono'>install_scripts = sandbox | deny | allowlist</font>. The adversarial escape suite (<font name='Mono'>LOOM_KERNEL_TESTS=1 cargo test -p loom-heddle --test escape</font>) attempts each forbidden action: read a canary in $HOME, read /etc/shadow, write a .pth into /usr, open TCP and UDP connections, nest a user namespace, ptrace, and leave a background process running. Every attempt must fail.")

# ------------------------------------------------------------------ 8
H1("8. Thread: independent rebuilders")
B("A rebuilder watches the AUR and, for each package version, (1) fetches the recipe and all pinned inputs, with no code executed; (2) builds <b>twice</b> under Heddle with deliberately different environments: time zone UTC vs Pacific/Chatham, locale C.UTF-8 vs fr_CH.UTF-8, umask 022 vs 002, and a different build path (the <i>reprotest</i> approach); (3) compares the two SHA-256 digests.")
L(["Both builds agree → outcome <b>reproducible</b>, with that digest as the artifact claim.",
   "Builds differ → <b>unreproducible</b>, and <i>no</i> digest claim is made.",
   "Build fails, or trips a hostile denial → <b>build_failed</b>, no claim (for example <i>refused: build attempted openat /root/.curlrc [FR-3.2], socket AF_INET [FR-3.4]</i>)."])
B("The rebuilder then signs the in-toto statement with its own Ed25519 key (FR-4.3), submits it to Warp (FR-4.4), stores the artifact in its content-addressed store, and serves it to peers. If other reproducible digests already exist for the same source commit, it lists them under <font name='Mono'>disputes</font>: a negative attestation (FR-4.6).")
B("<b>Self-verified contradictions (audit decision A6).</b> Only a rebuilder whose <i>own</i> two builds agreed may contradict another's artifact. A single flaky rebuilder therefore neither supports nor blocks an install, which bounds the denial-of-service power of one faulty rebuilder.")

# ------------------------------------------------------------------ 9
H1("9. Weave: the policy engine")
B("<font name='Mono'>loom_weave::evaluate(policy, evidence) → Decision</font> is a pure function. It evaluates <b>every</b> rule and reports every violation (FR-6.5); each failing rule carries its evidence and a remediation (FR-11.2), and no decision is ever an unexplained failure (FR-11.4). A policy decision takes about <b>8.3 µs</b>. Rule statuses are pass, info, overridden, warn and fail; any fail means BLOCK.")
T([["#", "Rule", "Requirement", "What it checks"],
   ["1", "continuity", "FR-8.x", "maintainer change (incl. orphan adoption), upstream signing-key change, history rewrite (git merge-base --is-ancestor), moved tags; evaluated first because an escalation raises k and extends quarantine"],
   ["2", "log", "FR-5.5–5.7", "the log verified (signature, cosignature threshold, consistency); unavailability degrades per policy"],
   ["3", "attestations", "FR-6.1–6.3", "≥ k independent, non-revoked, inclusion-verified attestations agree on the digest; else block / warn / allow per policy"],
   ["4", "contradiction", "FR-6.4", "any self-verified rebuilder attesting a different digest for the same source blocks, regardless of majority"],
   ["5", "quarantine", "FR-7.x", "version younger than min_age (default 72 h) is withheld unless the advisory feed marks it as a fix, or an override is recorded"],
   ["6", "sources", "FR-3.5", "all remote inputs pinned by hash; SKIP checksums and mutable VCS sources are refused"],
   ["7", "sandbox", "FR-3.x", "confinement achieved and tier; hostile denials fail even at exit 0"],
   ["8", "placement", "audit A4", "installed files that create persistence or privilege"],
   ["9", "install-scripts", "FR-9.2", "how install scripts will run: sandbox, deny or allowlist"]],
  [8 * mm, 24 * mm, 22 * mm, 120 * mm], "Weave's rules, in evaluation order.")
H2("9.1 Independence: maximum independent set")
B("Agreement from correlated rebuilders is not independent evidence (FR-6.2, NFR-SEC-4): two rebuilders run by the same organisation, or built with the same toolchain, can be compromised together. Weave builds a <b>correlation graph</b> whose vertices are agreeing attestations; an edge joins two attestations that share a rebuilder id, an organisation or a toolchain ID. The number of independent attestations is the size of a <b>maximum independent set</b> (the largest set of pairwise-uncorrelated vertices).")
C("for mask in 1 .. 2^n:                       # n ≤ 20: exact search with bitmasks\n    if popcount(mask) ≤ best: continue\n    if no two members of mask are adjacent: best = mask\nindependent = popcount(best)                 # n > 20: greedy bound (never over-counts)")
B("Example: thread-a (org-a, toolchain 1), thread-b (org-b, toolchain 2) and thread-c (org-c, toolchain 2) all agree. b and c share a toolchain, so the maximum independent set is {a, b} or {a, c}, and the count is 2, which meets the default k = 2. The graph formulation also collapses Sybil rebuilders that share an organisation.")
H2("9.2 Quarantine and the advisory fast-path")
B("Fast-moving attacks (worms, mass publication) are usually detected within days. Loom withholds any version published less than <font name='Mono'>min_age</font> ago (default 72 h, FR-7.1), reporting the publication time and the time remaining (FR-7.4). To avoid delaying security fixes, a version is exempt if the configured advisory feed (Arch Security Advisories JSON) lists it as fixing a vulnerability (FR-7.3). Version ranges are compared with a faithful port of libalpm's <font name='Mono'>rpmvercmp</font>, tested against pacman's own vectors.")
H2("9.3 Continuity of publishing authority")
B("At install, Loom records the maintainer, upstream signing keys (validpgpkeys) and recipe commit (FR-8.1). On the next evaluation it reports, with prior and current values and dates (FR-8.7): a maintainer change (FR-8.2), which includes orphan adoption (FR-8.5); a signing-key change (FR-8.3); and non-linear history (FR-8.4), proven with <font name='Mono'>git merge-base --is-ancestor old new</font>, so a force-push that rewrites history is detected even when the version number is unchanged. "
  "<b>Audit decision A2:</b> the same evidence is also drawn from the log's history (each attestation records the maintainer the AUR showed at build time), so a user installing an orphan-adopted package <i>for the first time</i>, with no local baseline, is still protected. The response is configurable: block (default), escalate (raise k, extend quarantine) or warn (FR-8.6).")
H2("9.4 Placement policy (audit decision A4)")
B("Some payloads are harmless at build time and dangerous only once installed; no build sandbox can see them (the LiteLLM .pth pattern). Loom inspects the artifact's file list before installing and blocks files that create persistence or privilege, for example:")
L(["<font name='Mono'>/usr/share/libalpm/hooks/</font>, <font name='Mono'>/etc/pacman.d/hooks/</font>: pacman hooks run as root on every future transaction",
   "<font name='Mono'>/etc/ld.so.preload</font>: preloads a library into every process",
   "Python <font name='Mono'>*.pth</font> files with import lines: execute on every interpreter start",
   "<font name='Mono'>/etc/sudoers</font>, <font name='Mono'>/etc/pam.d/</font>, <font name='Mono'>/usr/lib/security/</font>, <font name='Mono'>/etc/profile.d/</font>, cron directories, <font name='Mono'>/etc/systemd/system/</font>, systemd generators, <font name='Mono'>/etc/xdg/autostart/</font>, <font name='Mono'>/etc/ssh/</font>",
   "writes into /home, /root, /tmp, /run, /dev, /proc, /sys or /boot, and setuid/setgid binaries",
   "Lower-risk placements (udev rules, shipped-but-not-enabled services, sysctl.d, modules-load.d) produce a notice, not a block."])
H2("9.5 Policy file and overrides")
B("Policy is strict TOML (FR-9.1/9.2): unknown keys, invalid enum values and unparseable durations are fatal, and Loom refuses to run rather than fall back to permissive defaults (FR-9.4). With no file, a secure default applies (FR-9.3): k = 2, witness_threshold = 2, min_age = 72 h, install_scripts = sandbox, on_continuity_change = block, on_insufficient_attestations = warn. Every exception is an explicit, persistently recorded override (<font name='Mono'>loom override add &lt;kind&gt; &lt;pkg&gt; --reason \"…\"</font>) and is listed by the read-only <font name='Mono'>loom audit</font>.")

# ------------------------------------------------------------------ 10
H1("10. Shuttle: content-addressed distribution")
B("Shuttle provides <b>availability, never integrity</b>. The client asks several peers for the artifact by its SHA-256 digest, a digest that came from witness-cosigned attestations. Every byte received is hashed and compared; a peer serving corrupted data (ADV-7) is detected and skipped, and the client moves to the next peer or the origin (NFR-REL-1). The prototype uses a small HTTP peer protocol behind the fetch/PeerServer boundary; a libp2p (bitswap/Kademlia) transport could replace it without touching Weave, Warp or Thread.")

# ------------------------------------------------------------------ 11
H1("11. How each attack is defeated")
T([["Attack (real-world pattern)", "Mechanism(s) that stop it", "Demo"],
   ["Orphan adoption by a new maintainer (2026 AUR waves)", "Continuity (maintainer change) before building; rebuilders refuse the hostile build", "3"],
   ["Force-push / history rewrite (TeamPCP)", "Continuity (FR-8.4 via git ancestry); placement independently blocks the planted hook", "5"],
   ["npm install / payload fetch inside a PKGBUILD (Atomic Arch)", "Heddle denies network and credential reads; rebuilders refuse; Weave blocks even at exit 0", "4, 7"],
   ["Build-time credential harvest (Shai-Hulud, ChainDrop)", "Heddle: $HOME does not exist; hostile-denial rule", "4, 7"],
   ["Self-propagating worm", "No credentials reachable; quarantine delays spread", "2, 4"],
   ["Tampered artifact / compromised CI (LiteLLM, Axios)", "k-of-n reproducible rebuilds; contradiction rule", "E1"],
   ["Brand-new malicious release (mass publication)", "Temporal quarantine (72 h)", "2"],
   ["Persistence via pacman hook or ld.so.preload", "Placement policy; .INSTALL stripped and sandboxed", "5"],
   ["Python .pth startup hook (LiteLLM)", "Placement policy", "6"],
   ["Hostile log operator / split view", "Witness cosigning, quorum intersection, client cross-checks", "8"],
   ["Poisoned peer", "SHA-256 content addressing", "E1"]],
  [62 * mm, 92 * mm, 20 * mm], "Attack-to-defence mapping. Every mechanism is the sole catcher for at least one attack.")

# ------------------------------------------------------------------ 12
H1("12. Evaluation")
T([["Exp.", "Acceptance criterion", "Target", "Result"],
   ["E1", "Attack replay (AC-1)", "≥ 90% of malicious blocked before payload", "9 / 9 = 100%"],
   ["E2", "False positives (AC-2)", "≤ 5% spurious blocks", "0 / 7 = 0%"],
   ["E3", "Build compatibility (AC-3)", "measured and taxonomised", "measured in the live demo"],
   ["E4", "Ablation (AC-4)", "no single mechanism catches all", "best single: 3 / 9; five mechanisms used"],
   ["E5", "Overhead (AC-5)", "decision &lt; 500 ms; verification &lt; 100 ms", "8.3 µs; 60 µs (release build)"],
   ["E6", "Log integrity (AC-6)", "100% of split views detected", "200 / 200"]],
  [12 * mm, 44 * mm, 62 * mm, 56 * mm], "Results of the acceptance-criteria harness (cargo run -p loom-eval).")
FIG("demo-matrix", "Defence matrix from the live nine-scenario run: which mechanism stopped which package.")
B("<b>Sandbox contrast.</b> The same malicious build (npm-helper 2.5), run against a local canary sink: <b>0 hits</b> under Heddle and <b>1 hit</b> unconfined (<i>marker=loom-probe&amp;pkg=npm-helper&amp;stage=npm-install</i>). All malicious fixtures are inert probes that read a planted decoy and contact a local sink; nothing leaves the machine.")

# ------------------------------------------------------------------ 13
H1("13. Limitations and future work")
L(["<b>Simulated independence.</b> Rebuilders run on one host with divergent toolchain descriptors (ASM-4). A real deployment needs independent organisations with diverse toolchains.",
   "<b>Correspondence, not benignity.</b> Malicious source that every rebuilder faithfully reproduces is out of scope (OOS-5). The XZ Utils backdoor lived in the published source tarball, so rebuilding alone would not have flagged it. The witnessed log and <i>loom audit</i> make the response fast: one revocation reaches every client, and affected machines are identifiable.",
   "<b>Permissioned admission.</b> Open, Sybil-resistant rebuilder admission is unsolved.",
   "<b>Non-reproducible packages</b> never reach k and fall back to a sandboxed local build (warn by default).",
   "<b>Future work:</b> a federation of independent rebuilders and witnesses; npm, PyPI and crates.io backends (the engines need no change); a libp2p transport; diverse double-compiling against the Thompson attack; formal verification of Weave."])

# ------------------------------------------------------------------ 14
H1("14. Glossary")
T([["Term", "Meaning"],
   ["Attestation", "A signed statement by a rebuilder binding an artifact digest to a source commit, the rebuilder's identity and its toolchain"],
   ["Checkpoint", "The log's signed statement of its current size and root hash (a signed tree head)"],
   ["Content address", "Naming data by the hash of its bytes, so the name verifies the content"],
   ["Cosignature", "A witness's signature on a checkpoint, given only after a consistency check"],
   ["DSSE / PAE", "Dead Simple Signing Envelope; the Pre-Authentication Encoding it signs"],
   ["Inclusion / consistency proof", "Logarithmic-size proofs that a record is in the log, and that a newer log extends an older one"],
   ["k-of-n", "Requiring k independent agreeing attestations out of the n available"],
   ["Landlock", "An unprivileged Linux security module for self-imposed filesystem, TCP and IPC restrictions"],
   ["Orphan adoption", "Taking over maintenance of an abandoned AUR package"],
   ["Reproducible build", "A build that produces bit-identical output from the same source in different environments"],
   ["seccomp-BPF", "A kernel filter that runs a BPF program on every system call"],
   ["Split view", "A log showing different histories to different clients"],
   ["Witness", "An independent party that cosigns log checkpoints and vouches for one linear history"]],
  [44 * mm, 130 * mm])

# ------------------------------------------------------------------ refs
H1("References")
for r in refs:
    st.append(P(f"[{r['n']}] {r['cite']} <font color='#4455C7'>{r['url']}</font>", "small"))
    st.append(Spacer(1, 3))
H2("Standards and specifications implemented")
for k, c in [("S1", "NIST, “Secure Hash Standard (SHS),” FIPS PUB 180-4, 2015. https://doi.org/10.6028/NIST.FIPS.180-4"),
             ("S2", "S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm (EdDSA),” RFC 8032, IETF, 2017."),
             ("S3", "B. Laurie, A. Langley, and E. Kasper, “Certificate Transparency,” RFC 6962, IETF, 2013; B. Laurie, E. Messeri, and R. Stradling, “Certificate Transparency Version 2.0,” RFC 9162, IETF, 2021."),
             ("S4", "A. Rundgren, B. Jordan, and S. Erdtman, “JSON Canonicalization Scheme (JCS),” RFC 8785, IETF, 2020."),
             ("S5", "Secure Systems Lab, “DSSE: Dead Simple Signing Envelope, protocol v1.” https://github.com/secure-systems-lab/dsse"),
             ("S6", "in-toto, “in-toto Attestation Framework: Statement v1.” https://github.com/in-toto/attestation"),
             ("S7", "C2SP, “tlog-checkpoint,” “signed-note,” “tlog-cosignature” and “tlog-witness.” https://c2sp.org"),
             ("S8", "The Linux kernel documentation: “Landlock: unprivileged access control”; “Seccomp BPF (SECure COMPuting with filters)”; namespaces(7)."),
             ("S9", "LOOM-SRS-001, “Software Requirements Specification — Loom,” v1.0, structured per ISO/IEC/IEEE 29148:2018, Aug. 2026 (docs/SRS.md).")]:
    st.append(P(f"[{k}] {c}", "small")); st.append(Spacer(1, 3))

build(OUT, st, "Loom — Technical design and security report · Group 14")
print("wrote", OUT)
