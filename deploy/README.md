# multipass-server deployment contract

The production server runs on jax. Canonical private configuration, the systemd
unit, firewall policy, real routed prefix, real gateway endpoints, persistent
identity, and authorized scooter mapping live in
`vixen-central/infra/host/jax/`. This public directory documents the contract
with documentation-only addresses and keys; it is not deployment source.

Do not edit generated/live `/etc` or systemd files as source of truth. Do not
print, copy into logs, or replace either private key during routine deployment.

## Source-owned paths and service arguments

Jax uses:

| Artifact | Path | Policy |
| --- | --- | --- |
| release binary | `/usr/local/bin/multipass-server` | root-owned executable |
| typed config | `/etc/multipass-server/config.json` | root-owned, not group/world writable; atomically published from private source |
| persistent server key | `/var/lib/multipass-server/server.key` | root-only `0600`; create only when absent |

The service command is exactly:

```text
/usr/local/bin/multipass-server --config /etc/multipass-server/config.json
```

There are no positional bind-address or IPv6-prefix arguments. Reinstalling or
updating the binary must preserve the existing server identity and operator
config. Key rotation is an explicit coordinated operation because scooter pins
this identity.

## Exact server configuration shape

`ServerConfigFile` has exactly these JSON fields:

```json
{
  "private_key_file": "/var/lib/multipass-server/server.key",
  "bind": "0.0.0.0:51823",
  "routed_ipv6_prefix": "2001:db8:99::/64",
  "authorized_clients": [
    {
      "id": "scooter",
      "public_key": "ed25519:IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"
    }
  ]
}
```

`2001:db8::/32` and the shown Ed25519 values are documentation placeholders.
Private deployment source must contain the actual routed `/64` and scooter
public key before activation. The scooter key is public identity material, but
it must be obtained through an operator-controlled provisioning workflow; the
macOS installer never reveals or logs private key material.

The matching macOS client config pins jax's public key independently of all
reachable endpoint addresses. The same persistent jax identity is valid through
LAN IPv4, public IPv4, and public IPv6. QUIC negotiates ALPN `multipass/4`, and
both peers prove possession of their pinned/authorized Ed25519 keys.

## Build and artifact identity

Cross-build on scooter from the exact commit being deployed, install the binary,
and verify the installed artifact identity through the existing production
workflow:

```bash
COMMIT="$(git rev-parse HEAD)"
MULTIPASS_BUILD_COMMIT="$COMMIT" cargo zigbuild --target x86_64-unknown-linux-gnu --release -p multipass-server
scp target/x86_64-unknown-linux-gnu/release/multipass-server jax.vxn.rs:/tmp/
ssh jax.vxn.rs 'sudo install -m 0755 /tmp/multipass-server /usr/local/bin/multipass-server'
ssh jax.vxn.rs 'sudo systemctl restart multipass-server'
```

Build `multipassd` and the app from the same exact commit. After installing both
ends, query `benchmark_topology`: `daemon_version` must match the installed
client artifact and `server_version` must match `COMMIT`. The server identity is
reported only after an authenticated QUIC handshake; the daemon does not infer
it from its own source tree.

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

The plist value and both build identities in the topology reply must equal
`COMMIT`. A `connect` reply only acknowledges persistent enabled intent. The
bounded status loop waits for at least one mutually authenticated ready uplink.
While enabled but offline, `connected` remains false and `server_version` is
intentionally `unknown`.

## Endpoint and uplink behavior

Client configuration may list zero, one, or N logical uplinks. Each enabled
uplink independently races all compatible configured jax endpoints:

- home LAN IPv4;
- public IPv4;
- public IPv6.

The first candidate to complete pinned mutual authentication wins for that
uplink. Alternate jax addresses do not create extra scheduler capacity. No
current Ethernet/Wi-Fi address, default-gateway detection, or two-live-link
precondition exists at install time. An enabled client with zero ready uplinks
waits and automatically retries as native interface addresses/routes appear.

## IPv6 forwarding

The server config supplies a network-aligned routed IPv6 `/64`. Enable IPv6
forwarding in private source-owned router configuration:

```text
net.ipv6.conf.all.forwarding=1
```

Jax's WAN may use `IPv6AcceptRA=yes`. Linux normally ignores Router
Advertisements while forwarding; the private deployment must use the
appropriate per-interface `accept_ra=2` policy if the WAN default route depends
on RA.

### NAT66 mode

When using the current ULA `fd00:99::/64`, jax may masquerade it to the WAN
global address with an additive nftables rule:

```nft
 table ip6 nat {
     chain postrouting {
         type nat hook postrouting priority srcnat; policy accept;
         oifname "wan0" ip6 saddr fd00:99::/64 masquerade
     }
 }
```

`wan0` is intentionally a documentation name. Keep the real interface in
private source. IPv4 masquerading remains independent. Forwarding policy must
allow tunnel egress and established return traffic.

### Native routed mode

When a delegated prefix is available, select a `/64` for the tunnel, set that
network-aligned prefix in `routed_ipv6_prefix`, route it correctly, and omit the
NAT66 masquerade. The public repository must not contain the deployment prefix.

## Firewall

Admit UDP 51823 only according to the private router's intended LAN/WAN policy.
ICMPv6 must pass where required for errors and PMTU. Tunnel forwarding must
permit IPv4 and IPv6 egress plus established return traffic. Keep interface
names and real public addresses in private source.

## Benchmark listeners

The in-app benchmark uses sixteen systemd-managed iperf3 listeners on jax, TCP
ports 5210–5225. The canonical unit and firewall rules live in private
`vixen-central/infra/host/jax/` source. Ports are allocated per simultaneous
benchmark path so aggregate tests do not share an iperf server process.

```bash
ssh jax.vxn.rs 'systemctl is-active iperf3-benchmark@{5210..5225}.service'
ssh jax.vxn.rs 'sudo systemd-analyze verify /etc/systemd/system/iperf3-benchmark@.service'
ssh jax.vxn.rs 'sudo nft -c -f /etc/nftables.conf'
```

A configured uplink with no current source address remains in dynamic status
and benchmark topology but is unavailable for a physical-path benchmark.
Tunnel benchmarks can still run through whatever authenticated uplinks are
ready.
