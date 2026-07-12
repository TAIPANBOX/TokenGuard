# Contributing to tokenfuse

## Development

```sh
cargo build                                # build the workspace
cargo test --all                           # run tests
cargo fmt --all                            # format
cargo clippy --all-targets --all-features  # lint
```

Before every commit, this must be clean:

```sh
cargo fmt --all -- --check   # prints nothing
cargo clippy --all-targets --all-features
cargo test --all
```

CI also runs the cluster/raft integration test (`cargo test -p tokenfuse-gateway
--features cluster --test cluster_backend`), the Python and Node SDK test
suites, and builds the dashboard and OpenAPI spec. See `.github/workflows/ci.yml`
for the full gate.

## Conventions

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- Keep `tokenfuse-core` dependency-minimal; don't add web/serialization-heavy
  crates to it.
- Preserve byte-identical output on the enforcement hot path when refactoring
  (see the golden regression tests) - this is a spend kill-switch, and a
  behavior change there needs to be deliberate, not incidental.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.
