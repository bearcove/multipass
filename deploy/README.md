# multipass-server deployment on jax

The multipass server runs on jax (the router). The live systemd unit and
etckeeper-tracked config live in vixen-central under `infra/host/jax/`; this
directory documents the *delta* the aggregation+IPv6 build needs.

## Binary

Cross-build on scooter from the exact commit being deployed, install, and verify
that the installed binary carries that identity:

```bash
COMMIT="$(git rev-parse HEAD)"
MULTIPASS_BUILD_COMMIT="$COMMIT" cargo zigbuild --target x86_64-unknown-linux-gnu --release -p multipass-server
scp target/x86_64-unknown-linux-gnu/release/multipass-server jax.vxn.rs:/tmp/
ssh jax.vxn.rs 'sudo install -m 0755 /tmp/multipass-server /usr/local/bin/multipass-server'
ssh jax.vxn.rs 'sudo systemctl restart multipass-server'
```

`multipass-server` requires the deployment's routed IPv6 `/64` as its second
argument: `multipass-server 0.0.0.0:51823 <ipv6-prefix>/64`. Keep the real prefix
in the private router configuration; use documentation prefixes in this public
repository.

Build `multipassd` and the app from the same exact commit. After installing both
ends, query `benchmark_topology`: `daemon_version` must match the installed
client artifact and `server_version` must match `COMMIT`. The server identity is
reported by the live server during the QUIC handshake; `multipassd` does not
infer it from its own source tree.

Verify the installed app metadata and the authenticated daemon/server topology
with copy-pasteable production-path commands:

```bash
/usr/libexec/PlistBuddy -c 'Print :MultipassGitCommit' /Applications/Multipass.app/Contents/Info.plist
printf '%s\n' '{"cmd":"connect"}' | nc -U /var/run/multipassd.sock
for attempt in {1..50}; do
    STATUS="$(printf '%s\n' '{"cmd":"status"}' | nc -U /var/run/multipassd.sock)"
    [[ "$STATUS" == *'"connected":true'* ]] && break
    sleep 0.1
done
[[ "$STATUS" == *'"connected":true'* ]] || { echo "multipassd did not authenticate a server" >&2; exit 1; }
printf '%s\n' '{"cmd":"benchmark_topology"}' | nc -U /var/run/multipassd.sock
```

The plist value and both `daemon_version` and `server_version` in the topology
reply must equal `COMMIT`. The `connect` reply only acknowledges enablement, so
the bounded status loop waits for authenticated connectivity before querying
topology. While disconnected, `server_version` is intentionally `unknown`
because no server artifact is authenticated.

## IPv6 forwarding

Aggregation+IPv6 needs IPv6 forwarding enabled. IPv4 forwarding is already on
(`/etc/sysctl.d/90-router.conf`). Add to that file (etckeeper-tracked):

```
net.ipv6.conf.all.forwarding=1
```

Apply: `sudo sysctl --system` (or reboot). Verify:
`cat /proc/sys/net/ipv6/conf/all/forwarding` → `1`.

NOTE: jax's WAN uses `IPv6AcceptRA=yes`. Enabling forwarding makes the kernel
ignore Router Advertisements by default, which would drop the WAN default
route. If the WAN v6 default disappears after enabling forwarding, set
`net.ipv6.conf.enp5s0f1np1.accept_ra=2` (accept RA even when forwarding).

## NAT66 (current mode, until Freebox PD arrives)

The tunnel uses ULA `fd00:99::/64` (server `::1`, client `::2`). Jax
masquerades it to the WAN global address. Add an ip6 nat table (additive;
the existing IPv4 masquerade is untouched):

```
table ip6 nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "enp5s0f1np1" ip6 saddr fd00:99::/64 masquerade
    }
}
```

The existing `inet filter forward` chain already has `iifname "tun0" accept`
(tunnel → internet) and `ct state established,related accept` (return path),
so no forward change is needed for NAT66 outbound.

## Firewall

ICMPv6 must pass (PMTU, errors). The existing `meta l4proto ipv6-icmp accept`
in the input chain covers jax-local; ensure forward also permits ICMPv6 if a
drop would blackhole tunnel PMTU. Verify with `nft list chain inet filter forward`.

## Benchmark listeners

The in-app benchmark uses sixteen systemd-managed iperf3 listeners on jax,
TCP ports 5210–5225. The canonical unit and firewall rules live in
`vixen-central/infra/host/jax/`; `/etc` on jax is the etckeeper-tracked live
copy. Ports are allocated per simultaneous path so aggregate tests never share
an iperf server process.

```bash
ssh jax.vxn.rs 'systemctl is-active iperf3-benchmark@{5210..5225}.service'
ssh jax.vxn.rs 'sudo systemd-analyze verify /etc/systemd/system/iperf3-benchmark@.service'
ssh jax.vxn.rs 'sudo nft -c -f /etc/nftables.conf'
```

Firewall admission is limited to `10.10.10.0/24` on `br10`,
`10.10.99.0/24` on `tun0`, and `fd00:99::/64` on `tun0`. WAN, CI, and guest
interfaces do not gain access to the listener range.

## Native routed mode (after Freebox PD)

When the `/60` delegation arrives, replace NAT66:
- Assign a `/64` from the delegation to the tunnel in
  `crates/multipass-proto/src/lib.rs` (`TUNNEL_V6_*` constants).
- Remove the `table ip6 nat` masquerade.
- Route the delegated prefix to `tun0` and advertise/defend it on the WAN as
  required by the Freebox config.
