# SDD ledger — plan: docs/superpowers/plans/2026-08-11-n-uplink-roaming-vpn.md

Task 1: complete (commit 76f69b1 plus transport completion in 602538a; dynamic PathId/UplinkId/Hello metadata/Scheduler)
Task 3: partial in 602538a (dynamic Transport registry landed; Linux client and authenticated dial integration in progress)
Task 4: partial in 602538a (dynamic server registry and scheduler landed; pinned ClientId/TLS binding in progress)
Task 2: in progress — PinnedAuthConfig agent
Task 5: in progress — UnderlayLeases agent
Task 6: pending prerequisites; DaemonIntegrationTrace read-only analysis in progress
Task 7: in progress — SwiftDynamicUplinks agent
Task 8: pending Task 2 exact config schemas
Task 9: pending
Task 10: pending

Verified evidence before parallel prerequisite wave:
- cargo nextest run -p multipass-server: 20 passed
- Dynamic registration regressions include N=3, same-epoch generation replacement, stale/conflicting rejection, retired epoch side-effect safety, and new-epoch generation reset.
- Checkpoint commit 602538a: refactor: add dynamic uplink transport and sessions

Binding decisions after review:
- ClientId is added to Frame::Hello; wire ALPN bumps cleanly from multipass/3 to multipass/4.
- TLS-derived authorized ClientId must equal claimed Hello ClientId.
- Current tunnel addressing supports one active dataplane client; a second authorized ClientId must be explicitly rejected without mutating the first session until per-client address allocation exists.
- Production Transport dialing requires caller-supplied pinned mutual-auth ClientConfig; anonymous TLS helpers are test-only.
- IPC Connect means persistent enabled intent; connected means at least one authenticated ready uplink. Enabled with zero ready uplinks is a valid waiting state.
