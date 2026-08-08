# multipass

Seamless network failover for a Mac with two connections at once. Unplug the
Ethernet cable mid-SSH-session and nothing drops — the tunnel just keeps
flowing over Wi-Fi. Plug it back in, it comes back. Pull Wi-Fi instead, same
thing. No reconnect, no re-handshake, no "your session has been terminated."

macOS 27+ client, Linux server (runs on the router). All our own Rust + a
SwiftUI menubar app.

## Why this exists

At the desk, the MacBook is on **wired Ethernet and Wi-Fi at the same time**.
The moment you unplug the cable, every TCP/UDP session bound to the wired
interface's address dies. We wanted unplugging to be a non-event.

The off-the-shelf answer is **[mqvpn](https://github.com/mp0rta/mqvpn)** — a
multipath QUIC VPN that does exactly this. It's a fine piece of work and it
proved the concept for us. But it's a ~28k-line C binary that runs as **root**
and owns your routing table, and we weren't willing to hand it the keys
without a security review we didn't have the appetite for. So:

> **multipass is a loving reimplementation of just the part of mqvpn we care
> about, in Rust, on a stack we already trust (noq / QUIC).** Full respect to
> mp0rta — mqvpn showed the idea works and is far more feature-complete
> (Windows/Linux/Android, bandwidth aggregation, FEC, hybrid TCP lane, a real
> control API). If you want the mature, multiplatform thing, use mqvpn.
> multipass is the small, hackable, ours version.

We also tried plain **WireGuard + MPTCP** first. It can't do this on macOS:
MPTCP is per-app opt-in via Network.framework (your SSH client and browser
don't), and WireGuard roaming still stalls sessions for seconds on a path
drop. The seamless property needs multipath at the *packet* layer, not the
transport layer — which is the whole trick.

## How it works

One trick, and it's the entire thing:

- The client opens **two independent QUIC connections** to the server — one
  pinned to the wired interface, one to Wi-Fi.
- Every tunnel packet is sent on **both** connections (active-active).
- The receiver **dedups by sequence number** and keeps whichever copy arrives
  first.
- Unplug a cable → that connection's packets silently stop, the other
  connection is *already* delivering them. Nothing to fail over, nothing to
  re-establish. The gap is ~zero.

```
   your apps (ssh, browser, git — anything)
        │  plain IP, unchanged
        ▼
   ┌─────────────┐      ┌── conn A (en17, wired) ──┐
   │  utun dev   │─────►│                          │──► jax ──► internet
   │ (tun IP)    │      └── conn B (en0,  wifi)  ──┘
   └─────────────┘   every packet on both, dedup on receipt
     stable tunnel IP — apps never see the path change
```

Measured on the real desk (unplug eth, replug, unplug wifi, replug): **0.1%
packet loss, worst gap 184 ms**, and that spike is the interface coming *back*,
not the failure. The failure direction is effectively zero-gap.

## Status

**Early.** The transport (the hard part, the seamless-failover property) is
proven and working. The rest — the TUN device, routing, the menubar app, the
server-side forwarding — is being built. See `docs/ARCHITECTURE.md`.

## Layout

- `crates/multipass` — the client daemon (`multipassd`): utun + dual-connection
  transport + routing, runs as root on the Mac.
- `crates/multipass-proto` — the wire format (framing, dedup, control
  messages). Shared by client and server, no I/O.
- `crates/multipass-server` — the server (jax): decapsulate, forward, NAT.
- `app/` — the SwiftUI menubar app (macOS 27).

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache 2.0](LICENSE-APACHE), at your option.
