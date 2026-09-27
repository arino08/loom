# Loom — Configuration

Loom reads two files from its config directory (`/etc/loom`, or
`$LOOM_HOME/etc` when `LOOM_HOME` is set):

- **`loom.toml`** — *who is trusted* and *where they are* (the root of trust).
- **`policy.toml`** — *how much evidence is required* (optional; the built-in
  secure default applies when absent, FR-9.3).

Both are parsed strictly: unknown keys, bad enum values and unparseable
durations are fatal, so a typo can never silently weaken the policy (FR-9.4).
`loom policy validate` checks them; `loom policy show` prints the effective
policy plus warnings (including the witness-quorum analysis).

The demo generates both files for you: `loom-testbed provision` writes a
complete deployment under `$LOOM_HOME`. Use those files as worked examples.

## policy.toml

```toml
[policy]
min_age                      = "72h"      # temporal quarantine (FR-7.1)
required_attestations        = 2          # k of n independent rebuilds (FR-6.1)
witness_threshold            = 2          # cosignatures required on a checkpoint
install_scripts              = "sandbox"  # sandbox | deny | allowlist
on_continuity_change         = "block"    # block | escalate | warn
on_insufficient_attestations = "warn"     # block | warn | allow
# --- Loom extensions (see docs/ARCHITECTURE.md section 8) ---
continuity_window            = "30d"      # how far back log history is consulted
sandbox_min_tier             = "reduced"  # reduced | full  (refuse below this)
prefer_attested_artifact     = true       # verify-don't-build (audit A1)
placement                    = "block"    # block | warn  (audit A4)

[escalation]                              # applied on a continuity violation
required_attestations = 3
min_age               = "168h"

[advisory]
fast_path = true                          # security fixes skip quarantine (FR-7.3)
feed      = "https://security.archlinux.org/all.json"

[peer]
serve_cache             = true            # serve the local cache to peers (FR-2.4)
origin_fallback_timeout = "5s"

# Optional per-package overrides (FR-9.2):
[package.some-pkg]
min_age          = "1h"
allow_network    = true                   # a recorded FR-3.8 exception
allow_placement  = ["/usr/share/libalpm/hooks/"]
```

Durations accept `ms s m h d w` and combinations (`"1h30m"`). Every setting is a
"secure by default" choice: the shipped defaults are effective with no editing
(FR-9.3, NFR-USE-3).

## loom.toml

```toml
[aur]
rpc      = "https://aur.archlinux.org/rpc/v5"
git      = "https://aur.archlinux.org/{pkgbase}.git"
packages = "https://aur.archlinux.org/packages.gz"

[log]
url    = "https://warp.example/..."
origin = "example/warp"
key    = "example/warp+abcd1234+<base64>"   # the log's signed-note verifier key

[[witness]]
name = "witness-1"
key  = "<base64 ed25519 public key>"
url  = "https://witness-1.example"           # optional; enables cross-checking

[[rebuilder]]
id  = "thread-a"
org = "rebuild.example-a"                     # organisation, for independence
key = "<base64 ed25519 public key>"
url = "https://thread-a.example"              # serves artifacts by content address

[[revoker]]
name = "example-security"
key  = "<base64 ed25519 public key>"

[peers]
urls   = ["https://thread-a.example", "..."]
listen = "127.0.0.1:7781"                     # for `loom serve`

[install]
backend = "pacman"                            # pacman | root
# root = "/path"                              # required when backend = "root"

[sandbox]
backend = "kernel"                            # kernel | unconfined-demo
```

## Overrides

User-authorised exceptions are recorded persistently and surfaced by
`loom audit` (FR-3.8, FR-7.2):

```sh
loom override add quarantine   some-pkg 1.2-3 --reason "reviewed the diff"
loom override add continuity   some-pkg       --reason "trusted new maintainer"
loom override add attestations some-pkg 1.2-3 --reason "niche package, no rebuilders yet"
loom override add sandbox-network some-pkg    --reason "build legitimately downloads"
loom override add placement    some-pkg       --reason "known setuid helper"
loom override list
loom override rm 3
```

A continuity override is consumed once the new authority becomes the baseline,
so a *later* change is caught again.

## Keys and services (loomd)

```sh
loomd keygen  --out warp.key --name warp
loomd warp    --config warp.toml
loomd witness --config witness.toml
loomd thread  --config thread.toml --serve      # rebuilder + peer
loomd peer    --cas ./cas --listen 127.0.0.1:7731
loomd revoke  --key sec.key --log https://warp... --index 42 --reason "..." --revoker sec
```

Private keys are written mode 0600 and are never exported over the network
(NFR-SEC-2); Loom refuses to load a key file with looser permissions.
