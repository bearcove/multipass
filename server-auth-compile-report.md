# Server auth compile repair

## Scope

Updated only `crates/multipass-server/Cargo.toml`, `crates/multipass-server/src/config.rs`, and `crates/multipass-server/src/identity.rs`. `src/main.rs` required no source change: the active-client claim remains inside the successful `authenticate_uplink` transaction and its regression tests remain intact.

## Changes

- Removed the server's `multipass` dev-dependency and all `multipass::config` / `multipass::identity` imports, including test-only coupling.
- Added server-owned Ed25519 public-key parsing/formatting and strict SPKI extraction used consistently for configured pins, server identity derivation, TLS authorization, and `ClientId` lookup.
- Added server-owned secure file loading with `O_NOFOLLOW | O_CLOEXEC`, metadata obtained from the already-open handle, regular-file enforcement, exactly-one-hard-link enforcement, root ownership, config write restrictions, and private-key `0600`-or-stricter policy.
- Preserved atomic runtime loading: the validated config and securely read private key are still assembled into one `ServerRuntimeConfig` before the Tokio runtime starts.
- Preserved secret redaction in `ServerIdentity` debug output.
- Kept pinned TLS 1.3 mutual raw-public-key authentication. Server tests now build explicit mutual-auth client/server configs locally rather than importing the client daemon crate.
- Inspected installed `rustls 0.23.43` source. `DistinguishedName` is re-exported at `rustls::DistinguishedName`, and `ClientCertVerifier::root_hint_subjects` returns `&[DistinguishedName]`; the server implementation now uses those exact paths/signatures.
- Added a server-local regression for root/mode/link/regular-file metadata policy.

## Inspection evidence

- Source search found no `multipass::` references anywhere under `crates/multipass-server`.
- Source search found none of the forbidden insecure or compatibility APIs (`SkipVerify`, `with_no_client_auth`, `PathKind`, anonymous auth) under server production sources.
- `crates/multipass-server/Cargo.toml` no longer names `multipass`.

## Validation

Per assignment, no formatter, linter, build, or test command was run. Parent integration validation owns compile and test execution.
