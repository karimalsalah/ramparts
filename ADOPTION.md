# ADOPTION — ramparts (STEADYWRK estate)

Fork of [`highflame-ai/ramparts`](https://github.com/highflame-ai/ramparts). Adopted 2026-08-23 by the `moat` lane.
Estate record: `docs/strategy/OSS-ADOPTION-2026-08-23.md` in `karimalsalah/steadywrk` (PR #1465).

## What it is (verified live 2026-08-23)

Apache-2.0 · 96★ · last push 2026-08-21 · not archived · not a fork.
**Rust** (`Cargo.toml`), **5.0 MB** working tree. Source includes `config.rs`, `cache.rs`, `baseline.rs`, `banner.rs` — an **MCP security scanner**.

The smallest fork in the set by stars. Selected on **fit**, not popularity: it is the only verified-clean candidate that scans the exact surface we expose.

## Why we took it

steadywrk publishes an MCP storefront and **mints machine credentials** to strangers' agents (`/api/mcp/oauth/register` → `client_credentials`). That is an agent-facing attack surface we operate, and we currently scan it with nothing.

Two uses:
1. **Zero-trust on our own surface** — scan what we expose before someone else does.
2. **A Store Guard adjacency.** Agent-*readiness* and agent-*safety* will start being graded together; we already publish the readiness standard (`/store-guard/standard/v1`).

**What we take:** the scanner's check corpus and its findings model.

## Sequencing

**Third of five.** After `postcss-rtlcss` (controls proven) and `mcpc` (conformance). **Its first target is our own MCP endpoint — never a third party's.**

## Isolation — note the specific risk this codebase carries

`config.rs` and `cache.rs` are visible in the source tree. **Tools with config and cache modules very commonly write to a home-directory path** (`~/.config/<name>`, `~/.cache/<name>`) that no documented flag overrides. That is the precise failure mode the estate hit earlier the same day.

| Control | This fork |
|---|---|
| **Sandbox root** | `D:\forks\ramparts`. Never `C:`, never `~/.claude`, never `~/.cursor`. |
| **Kill-switch** | Delete `D:\forks\ramparts` **and** any home-directory config/cache dir the filesystem diff reveals. Deleting the repo alone is **not** assumed sufficient. |
| **Credentials** | **None.** Never `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or any production key. A scanner does not need a credential to scan a public surface — if it asks for one, that is a finding, not a requirement. |
| **Egress** | A scanner dials its target by definition. Separate *target* traffic from *telemetry* traffic; unexplained telemetry is a blocker. |
| **Target restriction** | **Only surfaces we own.** Scanning a third party's MCP server without authorisation is out of bounds — that is the estate's no-third-party rule, and it is not negotiable for convenience. |

## Required before any integration — the dry-run gate

1. **Filesystem diff — mandatory and expected to find something.** Snapshot `~/.claude`, `~/.cursor/mcp.json` (hash), **the whole home root**, and any `~/.config` / `~/.cache` entries, before and after first run. Diff. If it creates a home-directory path, record it here and treat containment as **empirically unresolved** until a working confinement is proven both ways (leak reproduced, then contained).
2. **Egress inventory.** Distinguish target traffic from telemetry.
3. **Capability proof.** Scan our own MCP endpoint; inspect findings for plausibility. **README claims are NOT verified** — only license, liveness, and non-archived status are.
4. **False-positive read.** Judge a sample of findings before trusting any of them. A scanner that cries wolf becomes an ignored control, which is worse than no control.

## The precedent driving these controls

On 2026-08-23 the estate adopted a tool and tested **five documented isolation flags — all five failed** to contain a write to a home-directory registry. Relocating `USERPROFILE` was the only containment that worked, and **only a before/after filesystem diff detected the leak at all**. A `doctor`/`status`/read-only-sounding subcommand still wrote outside its sandbox.

**Documented isolation is not proof of isolation.** For this fork, treat the home directory as presumed-at-risk until a diff says otherwise.

## Isolation inventory (repo review, 2026-10-08)

The record above predates these paths. Each one was read from source, not from a run.

- **Home writes:** `~/.ramparts/content-baseline.json` (`src/baseline.rs:35-41`, saved at `:175` and `:238`), `~/.ramparts/mcp-baseline.json` (`src/scanner.rs:1839-1845`), and the baseline saves in `src/main.rs:713` and `:741`. A successful scan creates these. A failed scan does not, so an empty `HOME` after failed runs proves nothing.
- **Home reads:** IDE config discovery under `~/.claude`, `~/.cursor`, `~/.vscode` and similar (`src/config.rs:971-1167`).
- **Egress, target traffic:** the MCP server being scanned, and for `stdio:` targets the launched command.
- **Egress, telemetry-like:** `https://api.osv.dev/v1/query` is queried for each `npx`/`uvx` stdio server, with no enable switch (`src/osv.rs:28`, `src/scanner.rs` around `1636-1642`).
- **Egress, LLM analysis:** when analysis runs, scanned tool definitions go to the configured endpoint. The default is `https://api.openai.com` (`src/config.rs:3677`). If `LLM_API_KEY` is unset, `OPENAI_API_KEY` is used (`src/security/mod.rs:283-286`). Setting `OPENAI_API_KEY` in this sandbox therefore sends scanned tool definitions to OpenAI. Do not set it.
- **Credentials:** none are needed. `RAMPARTS_API_TOKEN` is read only when the HTTP listeners run. It guards the listener and is not sent anywhere.
- **Kill-switch addition:** also delete `~/.ramparts/` if it exists.
- **Upstream:** this clone has only `origin` (`karimalsalah/ramparts`). The `upstream` remote named above is not configured here.
- **Gate still open:** the before-and-after filesystem diff must come from a *successful* scan. The review above did not run one, so `~/.ramparts` is unverified.

## Never

- Scan any MCP server we do not own.
- Point it at the live `C:\Users\youso\dev\steadywrk` checkout.
- Give it credentials.
- Merge upstream blindly — re-run the full gate after every version bump.

## Upstream

`upstream` = `highflame-ai/ramparts`. We track it; we do not push to it. Contributions go upstream as normal PRs under Apache-2.0.

- **2026-10-16 upstream bump:** merged `highflame-ai/ramparts` `main` at `14ff71e` (#152 semantic-release flow, #153 release tag fix; upstream deletes `cicd.yml`, `cron.yml` and `release-plz.yml`), ran a semver-compatible `cargo update`, moved the `yara-x` pin to `da19715d` (wasmtime 48.0.6) and swapped `serde_yaml` for `serde_norway` to clear RustSec findings. The dry-run gate above was **not** re-run for this bump and still needs running before any integration.
