# Security Policy

tokenfuse sits on the hot path between agents and their model provider and
enforces spend/policy decisions in real time, so its own trust boundaries
matter. This document covers how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately, not in public issues or PRs:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/tokenfuse/security/advisories/new>

Include the affected version/commit, a description, and a minimal reproduction.
We aim to acknowledge within a few days and to fix high-severity issues before
any public disclosure. There is no bug-bounty program; we credit reporters in
the advisory unless you prefer otherwise.

## Supported versions

tokenfuse is pre-1.0; only `main` is supported. Fixes land on `main` and are
not backported.

## Verifying a build

Every change must pass the full gate before merge: `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features`, and `cargo test --all`. CI also
runs `cargo audit` for known advisories in dependencies, plus the cluster/raft
integration test, Python/Node SDK tests, and dashboard build. See
[CONTRIBUTING.md](CONTRIBUTING.md).
