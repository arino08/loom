// Loom — Major Project Review deck (IEEE-style structure and citations).
const pptxgen = require("pptxgenjs");
const fs = require("fs");
const path = require("path");
const refs = JSON.parse(fs.readFileSync(path.join(__dirname, "refs.json"), "utf8"));

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in
pres.title = "Loom: A Decentralised, Verifying Package Manager for the AUR";
pres.subject = "Major Project Review";

// ---------------------------------------------------------------- palette
const C = {
  ink: "161B33", indigo: "2E3A8C", indigo2: "4455C7", soft: "E9ECF8", soft2: "F4F5FA",
  amber: "E0A526", amberSoft: "FBF1D8", text: "1B2030", muted: "5B6275", line: "CDD2E3",
  green: "2B7651", greenSoft: "DCEEE3", red: "B0352A", redSoft: "F6DFDB", white: "FFFFFF",
  tA: "3B5BDB", tB: "0B8A8E", tC: "9A4FB8",
};
const HF = "Cambria", BF = "Calibri", MF = "Courier New";
const W = 13.333;

// ---------------------------------------------------------------- helpers
function glyph(slide, x, y, s, dark) {
  // Woven motif: warp (indigo) under/over weft.
  const t = s * 0.13;
  [0.15, 0.45, 0.75].forEach((f) => slide.addShape(pres.shapes.RECTANGLE, { x: x + s * f - t / 2, y, w: t, h: s, fill: { color: dark ? "8C9BFF" : C.indigo2 }, line: { type: "none" } }));
  [0.2, 0.5, 0.8].forEach((f) => slide.addShape(pres.shapes.RECTANGLE, { x, y: y + s * f - t / 2, w: s, h: t, fill: { color: dark ? C.amber : C.ink }, line: { type: "none" } }));
  // over-crossings so it reads as woven
  [[0.15, 0.5], [0.45, 0.2], [0.45, 0.8], [0.75, 0.5]].forEach(([fx, fy]) =>
    slide.addShape(pres.shapes.RECTANGLE, { x: x + s * fx - t / 2, y: y + s * fy - t, w: t, h: t * 2, fill: { color: dark ? "8C9BFF" : C.indigo2 }, line: { type: "none" } }));
}

let slideNo = 0;
function content(section, title, notes) {
  const s = pres.addSlide();
  slideNo++;
  s.background = { color: C.white };
  s.addText(section, { x: 0.6, y: 0.35, w: 10.5, h: 0.32, fontFace: BF, fontSize: 12, bold: true, color: C.indigo2, charSpacing: 3, margin: 0, isTextBox: true });
  s.addText(title, { x: 0.6, y: 0.68, w: 11.2, h: 0.75, fontFace: HF, fontSize: 30, bold: true, color: C.ink, margin: 0, valign: "top", isTextBox: true });
  glyph(s, 12.25, 0.42, 0.5, false);
  s.addText("Loom — Major Project Review · 2026", { x: 0.6, y: 7.05, w: 6, h: 0.25, fontFace: BF, fontSize: 9, color: C.muted, margin: 0, isTextBox: true });
  s.addText(String(slideNo), { x: 12.2, y: 7.05, w: 0.55, h: 0.25, fontFace: BF, fontSize: 9, color: C.muted, align: "right", margin: 0, isTextBox: true });
  if (notes) s.addNotes(notes);
  return s;
}
function dark(notes) {
  const s = pres.addSlide();
  slideNo++;
  s.background = { color: C.ink };
  if (notes) s.addNotes(notes);
  return s;
}
function box(s, x, y, w, h, o = {}) {
  s.addShape(o.rounded === false ? pres.shapes.RECTANGLE : pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: o.rounded === false ? undefined : 0.08,
    fill: { color: o.fill || C.soft2 }, line: o.line ? { color: o.line, width: o.lw || 1, dashType: o.dash || "solid" } : { type: "none" },
    shadow: o.shadow ? { type: "outer", color: "000000", opacity: 0.12, blur: 6, offset: 2, angle: 90 } : undefined,
  });
}
function txt(s, text, x, y, w, h, o = {}) {
  s.addText(text, {
    x, y, w, h, fontFace: o.font || BF, fontSize: o.size || 14, color: o.color || C.text, bold: !!o.bold, italic: !!o.italic,
    align: o.align || "left", valign: o.valign || "top", margin: o.margin ?? 0, paraSpaceAfter: o.psa, lineSpacingMultiple: o.lsm, isTextBox: true, charSpacing: o.cs,
  });
}
// A labelled diagram node.
function node(s, x, y, w, h, title, sub, o = {}) {
  s.addText(
    [{ text: title, options: { bold: true, fontSize: o.ts || 13, color: o.tc || C.text, breakLine: !!sub } },
     ...(sub ? [{ text: sub, options: { fontSize: o.ss || 10, color: o.sc || C.muted, fontFace: o.subFont || BF } }] : [])],
    { shape: pres.shapes.ROUNDED_RECTANGLE, x, y, w, h, rectRadius: 0.06, fill: { color: o.fill || C.white },
      line: { color: o.line || C.indigo2, width: o.lw || 1.25, dashType: o.dash || "solid" }, fontFace: BF, align: o.align || "center", valign: "middle", margin: 0.05, isTextBox: true });
}
function arrow(s, x1, y1, x2, y2, o = {}) {
  s.addShape(pres.shapes.LINE, {
    x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1),
    flipH: x2 < x1, flipV: y2 < y1,
    line: { color: o.color || C.muted, width: o.width || 1.5, dashType: o.dash || "solid", endArrowType: o.noHead ? undefined : "triangle", beginArrowType: o.both ? "triangle" : undefined },
  });
}
function label(s, text, x, y, w, o = {}) {
  txt(s, text, x, y, w, 0.25, { size: o.size || 9.5, color: o.color || C.muted, italic: o.italic !== false, align: o.align || "center" });
}
function pill(s, text, x, y, w, fill, color) {
  s.addText(text, { shape: pres.shapes.ROUNDED_RECTANGLE, x, y, w, h: 0.3, rectRadius: 0.05, fill: { color: fill }, line: { type: "none" },
    fontFace: BF, fontSize: 10.5, bold: true, color, align: "center", valign: "middle", margin: 0, isTextBox: true });
}
function bullets(s, items, x, y, w, h, o = {}) {
  s.addText(items.map((it, i) => {
    const runs = typeof it === "string" ? [{ text: it }] : it;
    return runs.map((r, j) => ({ text: r.text, options: { bold: r.bold, color: r.color || o.color || C.text, fontFace: r.font || BF,
      bullet: j === 0 ? (o.numbered ? { type: "number" } : { indent: 16 }) : undefined, breakLine: j === runs.length - 1 && i < items.length - 1, paraSpaceAfter: o.psa ?? 8 } }));
  }).flat(), { x, y, w, h, fontFace: BF, fontSize: o.size || 15, color: o.color || C.text, valign: "top", margin: 0, isTextBox: true });
}

// Presenter tags for speaker notes.
const P = { 1: "Presenter 1 — Introduction & research (slides 1–7)", 2: "Presenter 2 — Architecture, flows & cryptography (slides 8–11)", 3: "Presenter 3 — Heddle & Weave (slide 12) and live demo part A", 4: "Presenter 4 — Live demo part B, results & conclusion (slides 13–16)" };

// ================================================================ 1. Title
{
  const s = dark(`${P[1]}. Greet the guide and jury, introduce Group 14 (Aiman Haque, Zoya Mulani, Aariz Sheikh, Yusuf Aslam), and state the one-line thesis: Loom makes installing community AUR packages safe without needing any cooperation from the AUR or its maintainers.`);
  // woven field on the right
  for (let i = 0; i < 9; i++) s.addShape(pres.shapes.RECTANGLE, { x: 8.7 + i * 0.5, y: 0, w: 0.14, h: 7.5, fill: { color: i % 3 === 1 ? C.amber : "2B3470" }, line: { type: "none" } });
  for (let j = 0; j < 12; j++) s.addShape(pres.shapes.RECTANGLE, { x: 8.55, y: 0.35 + j * 0.62, w: 4.8, h: 0.12, fill: { color: "3B4690" }, line: { type: "none" } });
  for (let i = 0; i < 9; i++) for (let j = 0; j < 12; j++) if ((i + j) % 2 === 0)
    s.addShape(pres.shapes.RECTANGLE, { x: 8.7 + i * 0.5, y: 0.3 + j * 0.62, w: 0.14, h: 0.22, fill: { color: i % 3 === 1 ? C.amber : "2B3470" }, line: { type: "none" } });
  s.addShape(pres.shapes.RECTANGLE, { x: 8.2, y: 0, w: 0.5, h: 7.5, fill: { color: C.ink }, line: { type: "none" } });
  txt(s, "MAJOR PROJECT · FINAL REVIEW", 0.7, 0.7, 7.4, 0.3, { size: 12, bold: true, color: C.amber, cs: 4 });
  txt(s, "Loom", 0.7, 1.15, 7.4, 1.1, { font: HF, size: 64, bold: true, color: C.white });
  txt(s, "A Decentralised, Verifying Package Manager for the Arch User Repository", 0.7, 2.3, 7.3, 1.2, { font: HF, size: 26, color: "DDE2FF" });
  txt(s, "Sandboxed builds · k-of-n reproducible attestations · a witnessed transparency log · authority-continuity checks", 0.7, 3.6, 7.2, 0.7, { size: 14, color: "AEB6DA", italic: true });
  txt(s, "GROUP NO. 14", 0.7, 4.45, 3.0, 0.3, { size: 11, bold: true, color: C.amber, cs: 3 });
  const team = [["Aiman Haque", "231415"], ["Zoya Mulani", "231435"], ["Aariz Sheikh", "231453"], ["Yusuf Aslam", "231460"]];
  team.forEach(([n, r], i) => {
    const x = 0.7 + (i % 2) * 3.55, y = 4.85 + Math.floor(i / 2) * 0.78;
    s.addShape(pres.shapes.RECTANGLE, { x, y: y + 0.06, w: 0.06, h: 0.52, fill: { color: i % 2 ? C.amber : "8C9BFF" }, line: { type: "none" } });
    txt(s, n, x + 0.2, y, 3.2, 0.36, { font: HF, size: 16, bold: true, color: C.white });
    txt(s, "Roll No. " + r, x + 0.2, y + 0.35, 3.2, 0.26, { size: 11.5, color: "AEB6DA" });
  });
  txt(s, "Guide: [Guide Name]  ·  Department of [Department]  ·  [Institution]  ·  September 2026", 0.7, 6.55, 7.4, 0.3, { size: 11, color: "AEB6DA" });
}

// ================================================================ 3. Abstract
{
  const s = content("ABSTRACT", "Abstract and index terms", `${P[1]}. Read the abstract's first sentence verbatim, then summarise: Loom does not try to detect malware; it contains builds and demands independent, publicly logged evidence before anything is installed. Point at the four numbers on the right; they are all from our own evaluation.`);
  s.addText([
    { text: "Abstract", options: { bold: true, italic: true } },
    { text: "—Community package repositories such as the Arch User Repository (AUR) execute unreviewed build scripts with the user's full privileges and install whatever a maintainer publishes, a weakness exploited by recent orphan-adoption, credential-harvesting and build-injection campaigns. We present Loom, a client-side, decentralised package manager that installs AUR packages under an enforceable trust policy without requiring cooperation from the AUR or its maintainers. Loom combines five independent mechanisms: (i) Heddle, a least-privilege build sandbox built from Linux namespaces, Landlock and seccomp-BPF; (ii) Thread and Weave, which accept an artifact only when k organisationally and toolchain-independent rebuilders reproduce it bit-for-bit; (iii) temporal quarantine with an advisory fast-path; (iv) publishing-authority continuity checks; and (v) Warp, an append-only, witness-cosigned Merkle transparency log that detects split views. Implemented in Rust and evaluated on a labelled incident corpus, Loom blocks 9/9 malicious cases with 0/7 false positives, detects 200/200 split-view trials, and adds microseconds of decision overhead." },
  ], { x: 0.6, y: 1.7, w: 8.3, h: 4.3, fontFace: HF, fontSize: 14.5, color: C.text, align: "justify", valign: "top", margin: 0, lineSpacingMultiple: 1.08, isTextBox: true });
  s.addText([{ text: "Index Terms", options: { bold: true, italic: true } }, { text: "—software supply chain security, reproducible builds, transparency logs, Merkle trees, Ed25519, sandboxing, Landlock, seccomp-BPF, package management, Arch User Repository." }],
    { x: 0.6, y: 5.75, w: 8.3, h: 0.75, fontFace: HF, fontSize: 12.5, color: C.muted, margin: 0, isTextBox: true });
  const stats = [["9 / 9", "malicious cases blocked (AC-1)", C.green], ["0 / 7", "benign packages blocked (AC-2)", C.green], ["200 / 200", "split-view trials detected (AC-6)", C.indigo2], ["60 µs", "per attestation signature check", C.indigo2]];
  stats.forEach(([v, l, c], i) => {
    const y = 1.7 + i * 1.3;
    box(s, 9.4, y, 3.35, 1.12, { fill: C.soft2 });
    txt(s, v, 9.6, y + 0.1, 3.0, 0.6, { font: HF, size: 32, bold: true, color: c });
    txt(s, l, 9.6, y + 0.72, 3.0, 0.32, { size: 11.5, color: C.muted });
  });
}

// ================================================================ 3. Introduction
{
  const s = content("I. INTRODUCTION", "Installing from the AUR means running a stranger's script", `${P[1]}. Left: the four steps of a normal AUR install with yay or paru. The PKGBUILD is a shell script that runs as you, so it can read ~/.ssh, ~/.aws and browser data and reach the network before pacman ever asks for root, and pacman then runs its install hooks as root. Nobody reviews AUR uploads and anyone can adopt an orphaned package [6]; XZ Utils showed how a patient takeover plus a build-script payload works [5]. Right: four numbers from peer-reviewed work that show the scale: 107 attack vectors [1], 24,356 malicious packages [4], three quarters reaching users through source installation [3], and under 1% of packages sandboxing themselves [15].`);
  const steps = [["1", "yay -S pkg", "helper fetches the PKGBUILD from AUR git"], ["2", "makepkg", "runs the PKGBUILD shell script as YOUR user"], ["3", "build()", "can read ~/.ssh, ~/.aws, tokens; open sockets"], ["4", "pacman -U", "installs as root; .INSTALL hooks run as root"]];
  steps.forEach(([n, t, d], i) => {
    const y = 1.75 + i * 1.12;
    s.addText(n, { shape: pres.shapes.OVAL, x: 0.6, y: y + 0.1, w: 0.58, h: 0.58, fill: { color: i >= 2 ? C.red : C.indigo }, line: { type: "none" }, fontFace: HF, fontSize: 17, bold: true, color: C.white, align: "center", valign: "middle", margin: 0, isTextBox: true });
    txt(s, t, 1.4, y + 0.03, 4.8, 0.38, { font: MF, size: 16, bold: true, color: C.ink });
    txt(s, d, 1.4, y + 0.43, 4.9, 0.36, { size: 13.5, color: C.muted });
    if (i < 3) arrow(s, 0.89, y + 0.7, 0.89, y + 1.2, { color: C.line, width: 2 });
  });
  box(s, 0.6, 6.25, 5.85, 0.55, { fill: C.redSoft });
  txt(s, "No review · no signing · orphans can be adopted by anyone", 0.8, 6.3, 5.5, 0.45, { size: 13, bold: true, color: C.red, valign: "middle" });
  const st = [["107", "attack vectors on OSS supply chains, mapped to 94 incidents", "[1] IEEE S&P 2023"], ["24,356", "malicious packages in the largest in-the-wild dataset", "[4] DSN 2025"], ["74.81%", "of malicious PyPI packages reached users via source installation", "[3] ASE 2023"], ["< 1%", "of packages directly use seccomp, Landlock or similar", "[15] SESoS 2024"]];
  st.forEach(([v, l, r], i) => {
    const x = 6.85 + (i % 2) * 3.0, y = 1.7 + Math.floor(i / 2) * 2.6;
    box(s, x, y, 2.85, 2.4, { fill: i === 2 ? C.amberSoft : C.soft2 });
    txt(s, v, x + 0.22, y + 0.2, 2.5, 0.75, { font: HF, size: 36, bold: true, color: i === 2 ? "8A5A00" : C.indigo });
    txt(s, l, x + 0.22, y + 0.98, 2.45, 0.95, { size: 12.5, color: C.text });
    txt(s, r, x + 0.22, y + 1.98, 2.45, 0.3, { size: 10.5, italic: true, color: C.muted });
  });
}

// ================================================================ 4. Problem, objectives, proposed system
{
  const s = content("II. PROBLEM STATEMENT & III. OBJECTIVES", "Problem, objectives and the five defences", `${P[1]}. Read the problem statement. Then the five objectives, each met by one Loom subsystem: Heddle contains builds, Thread and Weave verify artifacts through independent rebuilders, Quarantine slows down fast attacks, Continuity notices who changed, and Warp makes the evidence public and tamper-evident. Stress that they are independent: an attacker who defeats one still faces four. The footer states what we explicitly do not claim; that honesty matters (threat model OOS-1 to OOS-6).`);
  box(s, 0.6, 1.62, 12.15, 0.95, { fill: C.ink });
  txt(s, "Problem: install AUR packages only when there is independent, publicly verifiable evidence that the artifact matches its source, contain every build under least privilege, and detect changes of publishing authority — with no cooperation from the AUR, its maintainers or upstream.", 0.85, 1.68, 11.7, 0.85, { font: HF, size: 14, color: C.white, italic: true, valign: "middle" });
  const d = [
    ["Heddle", "build sandbox", "Contain every build", "Namespaces + Landlock + seccomp-BPF: no $HOME, credentials, network or writes outside the build dir.", "credential theft, build injection"],
    ["Thread + Weave", "k-of-n rebuilds", "Verify, don't trust", "Install only if k independent rebuilders reproduce the artifact bit-for-bit.", "artifacts that don't match source"],
    ["Quarantine", "temporal delay", "Slow down fast attacks", "Withhold versions younger than 72 h; advisory fast-path for security fixes.", "fast-moving worms"],
    ["Continuity", "authority tracking", "Notice who changed", "Detect maintainer, key and history changes, incl. orphan adoption and force-push.", "account takeover, orphan adoption"],
    ["Warp", "transparency log", "Make evidence public", "Append-only Merkle log, witness-cosigned; clients detect split views.", "hiding or forking the evidence"],
  ];
  d.forEach(([n, k, obj, desc, counters], i) => {
    const x = 0.6 + i * 2.46, y = 2.8;
    box(s, x, y, 2.28, 3.75, { fill: i % 2 ? C.soft2 : C.soft });
    s.addText(String(i + 1), { shape: pres.shapes.OVAL, x: x + 0.2, y: y + 0.2, w: 0.42, h: 0.42, fill: { color: C.indigo }, line: { type: "none" }, fontFace: HF, fontSize: 13, bold: true, color: C.white, align: "center", valign: "middle", margin: 0, isTextBox: true });
    txt(s, obj, x + 0.72, y + 0.16, 1.5, 0.5, { size: 11.5, bold: true, color: C.indigo, valign: "middle" });
    txt(s, n, x + 0.2, y + 0.78, 1.95, 0.4, { font: HF, size: 17, bold: true, color: C.ink });
    txt(s, k.toUpperCase(), x + 0.2, y + 1.17, 1.95, 0.25, { size: 9.5, bold: true, color: C.indigo2, cs: 1 });
    txt(s, desc, x + 0.2, y + 1.5, 1.92, 1.35, { size: 11.5, color: C.text });
    txt(s, "COUNTERS", x + 0.2, y + 2.9, 1.95, 0.22, { size: 9, bold: true, color: C.red, cs: 1 });
    txt(s, counters, x + 0.2, y + 3.12, 1.92, 0.55, { size: 11, color: C.text, italic: true });
  });
  txt(s, "Objective 6: explain every decision (FR-11). Out of scope: ≥ k colluding rebuilders, crypto breaks, kernel escapes, malicious source that all rebuilders reproduce.", 0.6, 6.62, 12.15, 0.4, { size: 10.5, italic: true, color: C.muted });
}
// ================================================================ 8–10. Literature review tables
function litSlide(rows, part) {
  const s = content("IV. LITERATURE REVIEW", `Literature review (${part} of 2)`, `${P[1]}. For each paper give one line on what it found and one line on the gap Loom addresses. Do not read the table; pick two or three highlights per slide. All sources are 2023 or later; full IEEE citations with links are in the References.`);
  const head = ["Ref.", "Work · Venue", "Key contribution", "Gap addressed by Loom"].map((t) => ({ text: t, options: { bold: true, color: C.white, fill: { color: C.indigo } } }));
  const body = rows.map((r, i) => [
    { text: `[${r.n}]`, options: { bold: true, color: C.indigo2, align: "center" } },
    { text: r.short, options: { bold: true } },
    { text: r.contrib },
    { text: r.gap, options: { color: C.green } },
  ].map((c) => ({ ...c, options: { ...c.options, fill: { color: i % 2 ? C.white : C.soft2 } } })));
  s.addTable([head, ...body], { x: 0.6, y: 1.65, w: 12.15, colW: [0.6, 2.35, 4.7, 4.5], rowH: [0.4, ...body.map(() => 0.58)], fontFace: BF, fontSize: 11, color: C.text, valign: "middle", border: { type: "solid", pt: 0.5, color: C.line }, margin: [4, 6, 4, 6], autoPage: false });
  return s;
}
litSlide(refs.slice(0, 8), 1);
litSlide(refs.slice(8, 16), 2);

// ================================================================ 11. Research gap
{
  const s = content("IV. LITERATURE REVIEW", "Research gap: no existing tool combines the defences", `${P[1]}. This is the key slide of the review. Each column is a class of existing solution; each row a property. Detection tools [2]-[4] are probabilistic. Signing [7],[8] needs registry cooperation the AUR does not offer. Reproducible-builds work [11],[12] measures reproducibility but never turns it into an install decision. Loom is the only column with every property, and it needs nothing from the AUR. Hand over to Presenter 2.`);
  const cols = ["yay / paru", "makepkg + chroot", "ML malware detection [2]–[4]", "Registry signing [7], [8]", "Reproducible builds [11], [12]", "Loom"];
  const rows = [
    ["Build runs without home/network access", "✗", "◐", "✗", "✗", "✗", "✓"],
    ["Independent k-of-n artifact verification", "✗", "✗", "✗", "✗", "◐", "✓"],
    ["Witnessed transparency log", "✗", "✗", "✗", "◐", "✗", "✓"],
    ["Detects change of publishing authority", "✗", "✗", "✗", "◐", "✗", "✓"],
    ["Quarantine of brand-new versions", "✗", "✗", "✗", "✗", "✗", "✓"],
    ["Blocks persistence placements (hooks, .pth)", "✗", "✗", "◐", "✗", "✗", "✓"],
    ["Works with zero registry cooperation", "✓", "✓", "✓", "✗", "◐", "✓"],
  ];
  const mark = (v, last) => ({ text: v, options: { align: "center", bold: true, fontSize: 15, color: v === "✓" ? C.green : v === "✗" ? C.red : "9C6A06", fill: { color: last ? C.greenSoft : C.white } } });
  const head = [{ text: "Property", options: { bold: true, color: C.white, fill: { color: C.ink } } }, ...cols.map((c, i) => ({ text: c, options: { bold: true, align: "center", color: C.white, fill: { color: i === 5 ? C.green : C.indigo } } }))];
  const body = rows.map((r) => [{ text: r[0], options: { bold: true, fill: { color: C.soft2 } } }, ...r.slice(1).map((v, i) => mark(v, i === 5))]);
  s.addTable([head, ...body], { x: 0.6, y: 1.65, w: 12.15, colW: [3.45, 1.4, 1.5, 1.6, 1.5, 1.6, 1.1], fontFace: BF, fontSize: 12, color: C.text, valign: "middle", border: { type: "solid", pt: 0.5, color: C.line }, margin: [5, 6, 5, 6], autoPage: false, rowH: 0.5 });
  txt(s, "✓ provided   ◐ partial / needs cooperation   ✗ not provided", 0.6, 6.55, 8, 0.3, { size: 11, color: C.muted, italic: true });
}

// ================================================================ 13. System architecture diagram
{
  const s = content("V. SYSTEM ARCHITECTURE", "System architecture", `${P[2]}. Walk the diagram left to right. The user talks only to the loom client. The client reads recipes from the AUR but never runs them to get metadata. Three rebuilders, run by different organisations, rebuild every package and submit signed attestations to Warp. Three witnesses cosign Warp's checkpoints after checking consistency proofs. Peers serve artifacts by hash. At the bottom: pacman does the final install, and the kernel provides the sandbox primitives. The dashed boundary is trust: nothing outside the client is trusted without a signature or hash check.`);
  // client boundary
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 2.35, y: 1.7, w: 4.3, h: 4.25, rectRadius: 0.1, fill: { color: C.soft }, line: { color: C.indigo, width: 1.5, dashType: "dash" } });
  txt(s, "loom client  (trusted computing base)", 2.5, 1.78, 4.0, 0.3, { size: 11.5, bold: true, color: C.indigo });
  node(s, 2.6, 2.2, 1.9, 0.75, "Weave", "policy engine", { fill: C.white });
  node(s, 4.55, 2.2, 1.9, 0.75, "Heddle", "build sandbox", { fill: C.white });
  node(s, 2.6, 3.1, 1.9, 0.75, "Warp client", "verify log + proofs", { fill: C.white });
  node(s, 4.55, 3.1, 1.9, 0.75, "Shuttle", "fetch by hash", { fill: C.white });
  node(s, 2.6, 4.0, 3.85, 0.7, "AUR backend (ecosystem seam)", ".SRCINFO parsing · git · vercmp", { fill: C.white });
  node(s, 2.6, 4.9, 3.85, 0.8, "State", "install DB · continuity baselines · overrides · verified log head", { fill: C.white, line: C.muted });
  // user
  node(s, 0.6, 3.1, 1.3, 0.8, "User", "loom CLI", { fill: C.ink, line: C.ink, tc: C.white, sc: "AEB6DA" });
  arrow(s, 1.9, 3.5, 2.35, 3.5, { color: C.ink, both: true });
  // external services
  node(s, 7.3, 1.7, 2.0, 0.75, "AUR", "RPC + git (read-only)", { line: C.muted });
  node(s, 7.3, 2.75, 2.0, 1.2, "Thread rebuilders ×3", "3 orgs · 3 toolchains\nbuild twice, sign in-toto", { line: C.tA });
  node(s, 7.3, 4.3, 2.0, 0.9, "Shuttle peers", "content-addressed store", { line: C.tB });
  node(s, 10.35, 1.55, 2.4, 0.85, "Witnesses ×3", "verify consistency, cosign", { line: C.green });
  node(s, 10.35, 2.75, 2.4, 1.2, "Warp log", "append-only Merkle tree\nsigned checkpoints", { line: C.indigo, lw: 2 });
  node(s, 2.35, 6.2, 2.05, 0.6, "pacman", "final install", { line: C.muted });
  node(s, 4.6, 6.2, 2.05, 0.6, "Linux kernel", "ns · Landlock · seccomp", { line: C.muted });
  // flows
  arrow(s, 7.3, 2.07, 6.65, 2.07, { color: C.muted }); label(s, "recipes", 6.62, 1.78, 0.7);
  arrow(s, 8.3, 2.45, 8.3, 2.75, { color: C.muted });
  arrow(s, 9.3, 3.35, 10.35, 3.35, { color: C.tA, width: 2 }); label(s, "attestations", 9.28, 3.05, 1.1, { color: C.tA });
  arrow(s, 11.55, 2.4, 11.55, 2.75, { color: C.green, width: 2, both: true }); label(s, "cosign", 11.65, 2.44, 0.8, { color: C.green, align: "left" });
  arrow(s, 8.3, 3.95, 8.3, 4.3, { color: C.tB });
  arrow(s, 7.3, 4.75, 6.65, 4.75, { color: C.tB, width: 2 }); label(s, "artifacts", 6.62, 4.8, 0.7, { color: C.tB });
  // Warp -> client: elbow under the peers box
  s.addShape(pres.shapes.LINE, { x: 11.55, y: 3.95, w: 0, h: 1.7, line: { color: C.indigo, width: 2 } });
  arrow(s, 11.55, 5.65, 6.65, 5.65, { color: C.indigo, width: 2 }); label(s, "signed checkpoint + cosignatures + inclusion/consistency proofs", 7.0, 5.33, 4.4, { color: C.indigo });
  arrow(s, 3.4, 5.95, 3.4, 6.2, { color: C.muted }); arrow(s, 5.6, 5.95, 5.6, 6.2, { color: C.muted });
  txt(s, "Every arrow into the client carries data that is verified by hash or signature before use (FR-2.6, NFR-SEC-1).", 7.3, 6.15, 5.45, 0.6, { size: 11.5, italic: true, color: C.muted });
}

// ================================================================ 15. Install flow
{
  const s = content("VI. METHODOLOGY", "Install flow: decide before anything runs", `${P[2]}. Follow the numbered path. Steps 1 to 3 run no package code at all: we parse .SRCINFO, never source the PKGBUILD. Step 4 is the Weave decision; if it blocks, the user gets the rule, the evidence and the fix, and nothing has executed. If allowed, we prefer the attested artifact fetched by its SHA-256 from peers, so when k rebuilders agree no PKGBUILD code ever runs on the user's machine. Only if no peer has it do we build locally inside Heddle. Then we inspect what the package installs, strip its .INSTALL so pacman never runs it as root, re-evaluate, and install.`);
  const st = [
    ["1", "Resolve", "AUR RPC; deps first"], ["2", "Fetch recipe", "parse .SRCINFO — no code runs"], ["3", "Gather evidence", "log · attestations · continuity · quarantine · advisories"], ["4", "Weave evaluate", "all rules, all violations"],
  ];
  const st2 = [
    ["5", "Obtain artifact", "by SHA-256 from peers; else Heddle build"], ["6", "Inspect", "placement · strip .INSTALL"], ["7", "Re-evaluate", "may still block (e.g. placement)"], ["8", "Install", "pacman -U · scripts in Heddle · record baseline"],
  ];
  const bw = 2.55, gap = 0.55;
  st.forEach(([n, t, d], i) => {
    const x = 0.6 + i * (bw + gap);
    node(s, x, 1.9, bw, 1.1, `${n}. ${t}`, d, { fill: i === 3 ? C.soft : C.white, line: i === 3 ? C.indigo : C.indigo2, lw: i === 3 ? 2 : 1.25 });
    if (i < 3) arrow(s, x + bw, 2.45, x + bw + gap, 2.45, { color: C.indigo2, width: 1.75 });
  });
  // decision diamond
  s.addText("blocked?", { shape: pres.shapes.DIAMOND, x: 9.95, y: 3.35, w: 1.7, h: 1.05, fill: { color: C.amberSoft }, line: { color: C.amber, width: 1.5 }, fontFace: BF, fontSize: 12, bold: true, color: C.text, align: "center", valign: "middle", margin: 0, isTextBox: true });
  arrow(s, 10.8, 3.0, 10.8, 3.35, { color: C.indigo2, width: 1.75 });
  node(s, 11.9, 3.35, 0.85, 1.05, "Refuse", "rule + fix", { fill: C.redSoft, line: C.red, tc: C.red, ts: 12, ss: 9.5 });
  arrow(s, 11.65, 3.87, 11.9, 3.87, { color: C.red, width: 1.75 }); label(s, "yes", 11.55, 3.55, 0.45, { color: C.red });
  // second row, right to left
  st2.forEach(([n, t, d], i) => {
    const x = 0.6 + (3 - i) * (bw + gap);
    node(s, x, 4.75, bw, 1.1, `${n}. ${t}`, d, { fill: i === 3 ? C.greenSoft : C.white, line: i === 3 ? C.green : C.indigo2, lw: i === 3 ? 2 : 1.25 });
    if (i < 3) arrow(s, x, 5.3, x - gap, 5.3, { color: C.indigo2, width: 1.75 });
  });
  arrow(s, 10.8, 4.4, 10.8, 4.75, { color: C.green, width: 1.75 }); label(s, "no", 10.85, 4.43, 0.4, { color: C.green, align: "left" });
  // re-evaluate can block too
  txt(s, "Steps 1–4 execute no package code (FR-3.9). If k rebuilders agree, no PKGBUILD code runs on the user's machine at all.", 0.6, 6.2, 12.1, 0.5, { size: 13, italic: true, color: C.indigo, bold: true });
}

// ================================================================ 16. Attestation sequence
{
  const s = content("VI. METHODOLOGY", "Attestation and logging flow (sequence)", `${P[2]}. Top to bottom in time. A rebuilder fetches the recipe, builds twice with deliberately different time zone, locale, umask and path, and compares the two SHA-256 digests. It signs an in-toto statement inside a DSSE envelope with its own Ed25519 key and submits it to Warp. Warp checks the signer is an admitted rebuilder, appends the leaf, signs a new checkpoint and sends it with a consistency proof to each witness. Witnesses verify the proof against the last size they cosigned and return a cosignature. The client later fetches the checkpoint, requires two of three cosignatures, verifies consistency with its saved head, and verifies inclusion of every attestation it uses.`);
  const lanes = [["AUR", C.muted], ["Thread rebuilder", C.tA], ["Warp log", C.indigo], ["Witness", C.green], ["loom client", C.ink]];
  const lx = (i) => 1.55 + i * 2.55;
  lanes.forEach(([n, c], i) => {
    node(s, lx(i) - 0.95, 1.65, 1.9, 0.5, n, null, { line: c, lw: 2, tc: c, ts: 12.5 });
    s.addShape(pres.shapes.LINE, { x: lx(i), y: 2.15, w: 0, h: 4.75, line: { color: C.line, width: 1.25, dashType: "dash" } });
  });
  const msg = (y, a, b, text, c, self) => {
    if (self) {
      s.addText(text, { shape: pres.shapes.ROUNDED_RECTANGLE, x: a === 4 ? lx(a) - 2.4 : lx(a) + 0.1, y: y - 0.17, w: 2.3, h: 0.36, rectRadius: 0.04, fill: { color: C.soft2 }, line: { color: c, width: 1 }, fontFace: BF, fontSize: 10.5, color: C.text, align: "center", valign: "middle", margin: 0, isTextBox: true });
      return;
    }
    arrow(s, lx(a), y, lx(b), y, { color: c, width: 1.6 });
    txt(s, text, Math.min(lx(a), lx(b)) + 0.1, y - 0.3, Math.abs(lx(b) - lx(a)) - 0.2, 0.27, { size: 10.5, color: C.text, align: "center" });
  };
  msg(2.55, 1, 0, "1. fetch recipe (git, pinned sources)", C.tA);
  msg(2.95, 1, 1, "2. build ×2 (TZ, locale, umask, path)", C.tA, true);
  msg(3.4, 1, 1, "3. SHA-256 equal? sign DSSE", C.tA, true);
  msg(3.9, 1, 2, "4. POST /add  in-toto statement", C.tA);
  msg(4.3, 2, 2, "5. admit · append leaf · sign", C.indigo, true);
  msg(4.8, 2, 3, "6. checkpoint + consistency proof", C.indigo);
  msg(5.2, 3, 3, "7. verify proof vs last size", C.green, true);
  msg(5.7, 3, 2, "8. cosignature/v1", C.green);
  msg(6.25, 2, 4, "9. checkpoint, cosigs, proofs", C.indigo);
  msg(6.65, 4, 4, "10. ≥2 cosigs · consistent", C.ink, true);
}

// ================================================================ 11. Crypto & Warp
{
  const s = content("VI. METHODOLOGY", "Cryptography and the Warp transparency log", `${P[2]}. Left: Loom invents no cryptography (CON-5). SHA-256 content-addresses every artifact and record. Ed25519 signs attestations, checkpoints and cosignatures, verified with verify_strict to reject malleable signatures. DSSE's pre-authentication encoding signs the length-prefixed payload type and body, so nothing can be spliced or reinterpreted, and because the in-toto predicate type is inside the signed body, an attestation signature can never be reused as a revocation. Canonical JSON makes signed bytes deterministic. The Merkle tree uses RFC 6962 domain separation, 0x00 for leaves and 0x01 for nodes. Right: to prove d2 is in the log, the server sends only the three amber sibling hashes, log2 of 8. Witnesses cosign a checkpoint only after checking a consistency proof from the last one they signed, so an honest witness vouches for one linear history. With 2 of 3 witnesses required, any two quorums share a witness, so a split view is prevented while at most one witness colludes. Hand over to Presenter 3.`);
  const head = ["Primitive", "Standard", "Used for"].map((t) => ({ text: t, options: { bold: true, color: C.white, fill: { color: C.indigo } } }));
  const rows = [
    ["SHA-256", "FIPS 180-4", "artifact/source digests, Merkle hashing, key & toolchain IDs"],
    ["Ed25519 (verify_strict)", "RFC 8032", "attestations, checkpoints, witness cosignatures"],
    ["DSSE PAE + in-toto", "DSSE v1", "length-prefixed, type-bound signing; signed predicateType"],
    ["Canonical JSON", "RFC 8785 subset", "deterministic signed bytes (sorted keys, no floats)"],
    ["Merkle tree", "RFC 6962 / 9162", "inclusion & consistency proofs, O(log n)"],
    ["Signed note, cosignature/v1", "C2SP", "checkpoint (alg 0x01), witness cosig (alg 0x04)"],
  ].map((r, i) => r.map((c, j) => ({ text: c, options: { bold: j === 0, fontFace: j === 1 ? MF : BF, fontSize: j === 1 ? 9.5 : 11, fill: { color: i % 2 ? C.white : C.soft2 } } })));
  s.addTable([head, ...rows], { x: 0.6, y: 1.62, w: 6.35, colW: [1.85, 1.35, 3.15], fontFace: BF, fontSize: 11, color: C.text, valign: "middle", border: { type: "solid", pt: 0.5, color: C.line }, margin: [3, 5, 3, 5], autoPage: false });
  box(s, 0.6, 5.2, 6.35, 1.6, { fill: C.ink });
  txt(s, "What is actually signed and hashed", 0.8, 5.28, 6.0, 0.28, { size: 10.5, bold: true, color: C.amber });
  txt(s, 'PAE  = "DSSEv1" SP len(type) SP type SP len(body) SP body\nsig  = Ed25519.Sign(sk_rebuilder, PAE)\nleaf = SHA-256(0x00 ‖ record)   node = SHA-256(0x01 ‖ L ‖ R)', 0.8, 5.6, 6.1, 1.1, { font: MF, size: 10.5, color: C.white });
  // Merkle tree (right)
  const lw = 0.5, ly = 4.1, lx0 = 7.25, lgap = 0.17;
  const leafX = (i) => lx0 + i * (lw + lgap);
  const path = new Set(["L2", "N1_1", "N2_0"]), sib = new Set(["L3", "N1_0", "N2_1"]);
  const nodeBox = (id, x, y, w, t) => s.addText(t, { shape: pres.shapes.ROUNDED_RECTANGLE, x, y, w, h: 0.36, rectRadius: 0.04,
    fill: { color: sib.has(id) ? C.amberSoft : path.has(id) ? C.soft : C.white }, line: { color: sib.has(id) ? C.amber : path.has(id) ? C.indigo : C.line, width: sib.has(id) || path.has(id) ? 1.75 : 1 },
    fontFace: MF, fontSize: 9, color: C.text, align: "center", valign: "middle", margin: 0, isTextBox: true });
  const cx = [];
  for (let i = 0; i < 8; i++) { nodeBox("L" + i, leafX(i), ly, lw, "d" + i); cx.push(leafX(i) + lw / 2); }
  let prev = cx;
  [[ly - 0.8, 4], [ly - 1.6, 2], [ly - 2.4, 1]].forEach(([y, n], k) => {
    const cur = [];
    for (let i = 0; i < n; i++) {
      const c = (prev[2 * i] + prev[2 * i + 1]) / 2, w = k === 2 ? 1.0 : 0.62;
      nodeBox(k === 2 ? "root" : `N${k + 1}_${i}`, c - w / 2, y, w, k === 2 ? "root" : `h${k + 1}.${i}`);
      [prev[2 * i], prev[2 * i + 1]].forEach((pc) => s.addShape(pres.shapes.LINE, { x: Math.min(pc, c), y: y + 0.36, w: Math.abs(c - pc), h: 0.44, flipH: pc < c, line: { color: C.muted, width: 1 } }));
      cur.push(c);
    }
    prev = cur;
  });
  pill(s, "on path", 10.6, 1.62, 0.95, C.soft, C.indigo); pill(s, "proof hash", 11.65, 1.62, 1.1, C.amberSoft, "8A5A00");
  txt(s, "Inclusion proof for d2 = 3 amber sibling hashes (log₂ 8)", 7.25, 4.55, 5.5, 0.28, { size: 10.5, italic: true, color: C.muted });
  box(s, 7.25, 4.95, 5.5, 1.85, { fill: C.soft });
  txt(s, "Witnesses stop split views", 7.45, 5.03, 5.1, 0.3, { font: HF, size: 14, bold: true, color: C.ink });
  txt(s, "Quorums of size t among n witnesses overlap in ≥ 2t − n. With t = 2, n = 3 they always share a witness, so a split view is prevented while ≤ 1 witness colludes. The client also checks the log signature, ≥ 2 cosignatures, consistency with its saved head, and inclusion of every record, and fails closed.", 7.45, 5.36, 5.15, 1.4, { size: 11, color: C.text });
}

// ================================================================ 12. Heddle & Weave
{
  const s = content("VI. METHODOLOGY", "Heddle sandbox and Weave policy engine", `${P[3]}. Left, Heddle: three nested layers. Namespaces give the build a fresh tmpfs root where the home directory simply does not exist, and an empty network namespace. Landlock is a kernel allow-list for files, TCP and IPC. seccomp-BPF refuses dangerous syscalls such as mount, ptrace, bpf and io_uring, and a supervisor explains each denial. Without user namespaces we run the reduced tier; without Landlock we refuse to build, never an unconfined fallback. A build that even tries to read credentials or use the network is rejected, even if it exits 0. Right, Weave: evaluates all nine rules and reports every violation with a fix. The key algorithm is independence: attestations sharing a rebuilder, organisation or toolchain are correlated, and the count is the maximum independent set. Here B and C share a toolchain, so three attestations count as two, which still meets k = 2.`);
  txt(s, "HEDDLE — least-privilege build sandbox", 0.6, 1.62, 6.0, 0.3, { size: 12, bold: true, color: C.indigo2, cs: 1 });
  const layers = [["Namespaces: user · mount · net · pid · ipc · uts · cgroup", C.indigo, C.soft], ["Landlock (ABI ≤ v6): files · TCP · IPC scope", C.indigo2, "DDE3FA"], ["seccomp-BPF + supervisor: EPERM mount, ptrace, bpf, io_uring…", C.tB, "D6F0F0"]];
  layers.forEach(([t, c, f], i) => {
    const inset = i * 0.42;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6 + inset, y: 2.0 + inset, w: 5.95 - 2 * inset, h: 3.2 - 2 * inset, rectRadius: 0.1, fill: { color: f }, line: { color: c, width: 2 } });
    txt(s, t, 0.78 + inset, 2.08 + inset, 5.6 - 2 * inset, 0.3, { size: 10.5, bold: true, color: c });
  });
  node(s, 2.1, 3.3, 2.95, 1.05, "build()", "PKGBUILD / install script, ordinary user,\npivot_root tmpfs: $HOME does not exist", { fill: C.white, line: C.ink, lw: 2, ts: 14, ss: 9.5 });
  [["FULL", C.green, C.greenSoft], ["REDUCED", "8A5A00", C.amberSoft], ["REFUSED", C.red, C.redSoft]].forEach(([t, c, f], i) => pill(s, t, 0.6 + i * 1.3, 5.38, 1.2, f, c));
  txt(s, "never an unconfined fallback", 4.55, 5.4, 2.1, 0.28, { size: 10.5, italic: true, color: C.muted });
  box(s, 0.6, 5.85, 5.95, 0.95, { fill: C.redSoft });
  txt(s, "Hostile = any FR-3.2 credential read or FR-3.4 network socket → rebuilders refuse to attest and Weave blocks, even if the build exits 0 (|| true).", 0.78, 5.9, 5.6, 0.85, { size: 11.5, color: C.text, valign: "middle" });
  // Weave
  txt(s, "WEAVE — explainable policy evaluation", 6.95, 1.62, 5.8, 0.3, { size: 12, bold: true, color: C.indigo2, cs: 1 });
  const rules = ["continuity", "log", "attestations", "contradiction", "quarantine", "sources", "sandbox", "placement", "install-scripts"];
  rules.forEach((r, i) => {
    const x = 6.95 + (i % 3) * 1.95, y = 2.0 + Math.floor(i / 3) * 0.45;
    s.addText(`${i + 1}. ${r}`, { shape: pres.shapes.ROUNDED_RECTANGLE, x, y, w: 1.85, h: 0.36, rectRadius: 0.04, fill: { color: i === 0 ? C.indigo : C.soft }, line: { color: C.indigo2, width: 1 }, fontFace: MF, fontSize: 9.5, bold: true, color: i === 0 ? C.white : C.indigo, align: "center", valign: "middle", margin: 0, isTextBox: true });
  });
  box(s, 6.95, 3.45, 5.8, 2.1, { fill: C.soft2 });
  txt(s, "k-of-n independence = maximum independent set", 7.1, 3.52, 5.5, 0.3, { font: HF, size: 13, bold: true, color: C.ink });
  node(s, 7.2, 4.15, 1.5, 0.6, "thread-a", "org-a · tc 1", { line: C.tA, lw: 2, ts: 11.5, ss: 9 });
  node(s, 9.25, 3.9, 1.5, 0.6, "thread-b", "org-b · tc 2", { line: C.tB, lw: 2, ts: 11.5, ss: 9 });
  node(s, 9.25, 4.85, 1.5, 0.6, "thread-c", "org-c · tc 2", { line: C.tC, lw: 2, ts: 11.5, ss: 9 });
  s.addShape(pres.shapes.LINE, { x: 10.0, y: 4.5, w: 0, h: 0.35, line: { color: C.red, width: 2.5, dashType: "dash" } });
  txt(s, "same toolchain → correlated\n3 agree → count 2 ≥ k = 2 → PASS", 10.9, 4.15, 1.8, 1.0, { size: 10.5, bold: true, color: C.green });
  bullets(s, [
    [{ text: "Contradiction: ", bold: true }, { text: "any self-verified rebuilder with a different digest blocks." }],
    [{ text: "Quarantine: ", bold: true }, { text: "< 72 h old → withhold; advisory fast-path for CVE fixes." }],
    [{ text: "Placement: ", bold: true }, { text: "pacman hooks, ld.so.preload, .pth, PAM, setuid → block." }],
  ], 6.95, 5.68, 5.8, 1.15, { size: 11, psa: 3 });
}

// ================================================================ 13. Results
{
  const s = content("VII. RESULTS & EVALUATION", "Results: every checked acceptance criterion passes", `${P[4]}. Our SRS defines six experiments. E1: all nine malicious cases in the labelled incident corpus are blocked before any payload runs. E2: none of the seven benign packages is blocked, even though they deliberately stress each mechanism. E3 is a measurement rather than a gate. E4, the chart: detections are spread over five mechanisms and the best single one catches only three of nine, so no single bypass defeats Loom. E5: a decision takes 8.3 microseconds and an Ed25519 verification 60 microseconds in a release build. E6: 200 of 200 split views detected. And the headline: the same malicious build against a canary sink produced zero hits under Heddle and one hit unconfined.`);
  const head = ["Exp.", "Criterion", "Target", "Result", ""].map((t) => ({ text: t, options: { bold: true, color: C.white, fill: { color: C.indigo } } }));
  const rows = [
    ["E1", "Attack replay (AC-1)", "≥ 90% blocked", "9 / 9 = 100%", "PASS"], ["E2", "False positives (AC-2)", "≤ 5% blocked", "0 / 7 = 0%", "PASS"],
    ["E3", "Build compatibility (AC-3)", "measured", "measured in live demo", "N/A*"], ["E4", "Ablation (AC-4)", "no single mechanism", "best single: 3 / 9", "PASS"],
    ["E5", "Overhead (AC-5)", "< 500 ms · < 100 ms", "8.3 µs · 60 µs", "PASS"], ["E6", "Split view (AC-6)", "100% detected", "200 / 200", "PASS"],
  ].map((r, i) => r.map((c, j) => ({ text: c, options: { bold: j === 0 || j === 3 || j === 4, align: j === 4 ? "center" : "left", color: j === 4 ? (c === "PASS" ? C.green : "9C6A06") : C.text, fill: { color: i % 2 ? C.white : C.soft2 } } })));
  s.addTable([head, ...rows], { x: 0.6, y: 1.62, w: 6.6, colW: [0.55, 2.2, 1.6, 1.6, 0.65], fontFace: BF, fontSize: 11.5, color: C.text, valign: "middle", border: { type: "solid", pt: 0.5, color: C.line }, margin: [4, 5, 4, 5], autoPage: false, rowH: 0.44 });
  txt(s, "* AC-3 is a measurement, not a pass/fail gate (SRS §8).", 0.6, 4.78, 6.6, 0.26, { size: 10, italic: true, color: C.muted });
  s.addChart(pres.charts.BAR, [{ name: "Malicious cases caught", labels: ["Contradiction", "Quarantine", "Placement", "Continuity", "Sandbox"], values: [1, 1, 2, 2, 3] }], {
    x: 7.45, y: 1.55, w: 5.3, h: 3.5, barDir: "bar", chartColors: [C.indigo2], showValue: true, dataLabelPosition: "outEnd", dataLabelColor: C.text, dataLabelFontSize: 11,
    showTitle: true, title: "E4 ablation: malicious cases caught per mechanism (of 9)", titleFontSize: 12, titleColor: C.ink, titleFontFace: BF,
    catAxisLabelColor: C.text, catAxisLabelFontSize: 11, valAxisLabelColor: C.muted, valAxisMaxVal: 4, valAxisMinVal: 0, valAxisMajorUnit: 1,
    valGridLine: { color: "E5E7EF", size: 0.5 }, catGridLine: { style: "none" }, showLegend: false, barGapWidthPct: 60,
  });
  const tiles = [["8.3 µs", "policy decision (target < 500 ms)", C.indigo, C.soft2], ["60 µs", "Ed25519 verification (target < 100 ms)", C.indigo, C.soft2], ["0", "sink hits — malicious build under Heddle", C.green, C.greenSoft], ["1", "sink hit — same build unconfined", C.red, C.redSoft]];
  tiles.forEach(([v, l, c, f], i) => {
    const x = 0.6 + i * 3.08;
    box(s, x, 5.2, 2.9, 1.6, { fill: f });
    txt(s, v, x + 0.22, 5.28, 2.5, 0.75, { font: HF, size: 34, bold: true, color: c });
    txt(s, l, x + 0.22, 6.05, 2.55, 0.65, { size: 12, color: C.text });
  });
}
{
  const s = content("VIII. LIVE DEMONSTRATION", "Live demonstration: nine attacks on a real deployment", `${P[4]}. This recaps the live demo. Rows are the nine scenarios, columns the mechanisms. Red cells are where a mechanism stopped a package in our run. Notice the red cells are spread over every column: that is the ablation result reproduced live. Scenario 8's only red cell is the Warp witnesses column: the forked log was rejected by the victim's client.`);
  const mech = ["Continuity", "Quarantine", "k-of-n rebuilds", "Heddle sandbox", "Placement", "Warp witnesses"];
  const B = (t) => ({ text: t, options: { bold: true, color: C.white, fill: { color: C.red }, align: "center" } });
  const Rf = (t) => ({ text: t, options: { bold: true, color: C.red, fill: { color: C.redSoft }, align: "center" } });
  const ok = () => ({ text: "✓", options: { color: C.green, align: "center", bold: true } });
  const na = () => ({ text: "·", options: { color: C.line, align: "center" } });
  const res = (t, good) => ({ text: t, options: { bold: true, color: good ? C.green : C.red, align: "center" } });
  const rows = [
    ["1  Healthy package", ok(), ok(), ok(), ok(), ok(), ok(), res("2 ALLOWED", true)],
    ["2  Quarantine + fast-path", ok(), B("fastmover"), ok(), ok(), ok(), ok(), res("1 of 2 BLOCKED")],
    ["3  Orphan adoption", B("orphan-tool"), ok(), ok(), Rf("rebuilders refused"), ok(), ok(), res("1 of 2 BLOCKED")],
    ["4  npm install in PKGBUILD", ok(), ok(), ok(), B("npm-helper"), ok(), ok(), res("1 of 2 BLOCKED")],
    ["5  Force-push + pacman hook", B("forcepush-lib"), ok(), ok(), ok(), B("forcepush-lib"), ok(), res("2 of 3 BLOCKED")],
    ["6  .pth startup hook", ok(), ok(), ok(), ok(), B("pth-inject"), ok(), res("1 of 1 BLOCKED")],
    ["7  Confined vs unconfined", ok(), ok(), ok(), B("npm-helper"), ok(), ok(), res("1 of 2 BLOCKED")],
    ["8  Split-view attack", na(), na(), na(), na(), na(), B("fork rejected"), res("FORK REJECTED")],
    ["9  Provenance audit", B("orphan-tool"), ok(), ok(), ok(), ok(), ok(), res("1 of 3 BLOCKED")],
  ].map((r, i) => r.map((c, j) => { const o = typeof c === "string" ? { text: c, options: { bold: true } } : c; return { text: o.text, options: { ...o.options, fill: o.options.fill || { color: i % 2 ? C.white : C.soft2 } } }; }));
  const head = [{ text: "Scenario", options: { bold: true, color: C.white, fill: { color: C.ink } } }, ...mech.map((m) => ({ text: m, options: { bold: true, color: C.white, align: "center", fill: { color: C.indigo } } })), { text: "Result", options: { bold: true, color: C.white, align: "center", fill: { color: C.ink } } }];
  s.addTable([head, ...rows], { x: 0.6, y: 1.65, w: 12.15, colW: [2.65, 1.45, 1.35, 1.35, 1.5, 1.45, 1.35, 1.05], fontFace: BF, fontSize: 11, color: C.text, valign: "middle", border: { type: "solid", pt: 0.5, color: C.line }, margin: [3, 4, 3, 4], autoPage: false, rowH: 0.47 });
  txt(s, "Red: this check stopped the package · pink: no rebuilder would attest it · ✓ evaluated and passed · from the live run's event journal; live console at http://127.0.0.1:7790", 0.6, 6.6, 12.1, 0.3, { size: 11, italic: true, color: C.muted });
}
// ================================================================ 15. Conclusion
{
  const s = dark(`${P[4]}. Deliver the four conclusions slowly, then be candid about limitations: rebuilder independence is simulated on one host, attestation proves an artifact matches its source but not that the source is benign, and log admission is permissioned. Future work follows directly. End on "Thank you" and invite questions; each presenter answers questions in their own area.`);
  glyph(s, 0.7, 0.55, 0.55, true);
  txt(s, "IX. CONCLUSION", 1.45, 0.68, 8, 0.35, { size: 12, bold: true, color: C.amber, cs: 4 });
  txt(s, "Loom turns installing community software into a verifiable decision instead of an act of faith.", 0.7, 1.25, 11.9, 1.0, { font: HF, size: 26, bold: true, color: C.white });
  const pts = [["Contain", "No home directory, credentials or network for any build; hostile attempts rejected even at exit 0."], ["Verify", "Installed only when independent rebuilders reproduce it, recorded in a witnessed log."], ["Detect", "Orphan adoption, force-pushes, fresh releases and persistence placements caught before install."], ["Explain", "Every decision names its rule, its evidence and the command to proceed."]];
  pts.forEach(([t, d], i) => {
    const x = 0.7 + i * 3.05;
    txt(s, t, x, 2.45, 2.8, 0.4, { font: HF, size: 19, bold: true, color: C.amber });
    txt(s, d, x, 2.9, 2.8, 1.0, { size: 12, color: "DDE2FF" });
  });
  const col = (x, t, items, c) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 4.1, w: 5.9, h: 2.15, rectRadius: 0.08, fill: { color: "232A55" }, line: { type: "none" } });
    txt(s, t, x + 0.25, 4.2, 5.4, 0.35, { font: HF, size: 15, bold: true, color: c });
    bullets(s, items, x + 0.25, 4.62, 5.45, 1.6, { size: 13, color: "DDE2FF", psa: 7 });
  };
  col(0.7, "Limitations", ["Rebuilder independence simulated on one host (ASM-4).", "Proves artifact = source, not that the source is benign (OOS-5).", "Permissioned log admission; non-reproducible packages never reach k."], "FF9E8F");
  col(6.75, "Future work", ["A real federation of independent rebuilders and witnesses.", "npm / PyPI / crates.io backends: engines unchanged (NFR-MNT-1).", "libp2p transport; diverse double-compiling; verified Weave."], "8FE0B5");
  txt(s, "Thank you — questions welcome", 0.7, 6.5, 7.5, 0.5, { font: HF, size: 22, bold: true, color: C.white });
  txt(s, "9/9 attacks blocked · 0 false positives · 200/200 split views detected", 7.9, 6.58, 4.85, 0.4, { size: 11.5, italic: true, color: "AEB6DA", align: "right" });
}

// ================================================================ 16. References
{
  const s = content("REFERENCES", "References", `${P[4]}. Leave on screen during questions. All sixteen are peer-reviewed or preprint research from 2023 onward. The standards Loom implements (FIPS 180-4, RFC 8032, RFC 6962/9162, RFC 8785, DSSE, in-toto, C2SP) are cited in the technical document.`);
  const colRefs = (list, x) => s.addText(list.map((r, i) => [
    { text: `[${r.n}] `, options: { bold: true, color: C.indigo } },
    { text: r.cite + " " },
    { text: r.url, options: { color: C.indigo2, hyperlink: { url: r.url }, breakLine: i < list.length - 1 } },
  ]).flat(), { x, y: 1.55, w: 5.95, h: 5.25, fontFace: BF, fontSize: 9.5, color: C.text, valign: "top", margin: 0, paraSpaceAfter: 5, isTextBox: true });
  colRefs(refs.slice(0, 8), 0.6);
  colRefs(refs.slice(8, 16), 6.8);
  txt(s, "Standards implemented (FIPS 180-4, RFC 8032, RFC 6962/9162, RFC 8785, DSSE, in-toto, C2SP) are cited in the accompanying technical document.", 0.6, 6.82, 12.15, 0.22, { size: 9, italic: true, color: C.muted });
}

pres.writeFile({ fileName: path.join(__dirname, "Loom_Major_Project_Presentation.pptx") }).then((f) => console.log("wrote", f));
