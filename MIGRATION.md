# Go → Rust migration plan

Goal: replace the Go implementation with Rust, and finish it to a working
userspace WireGuard peer — **protocol library + blocking-IO UDP daemon, no TUN
device**.

Concurrency model: plain OS threads and blocking sockets, shared state behind
`Arc<Mutex<…>>`. No async runtime. A few peers over one UDP socket has no
scheduling problem that async solves, and this keeps the handshake state machine
readable. `UdpSocket::send_to` takes `&self`, so the socket lives in a bare `Arc`
with no lock — only the peer and session tables are mutexed.

Threads in the finished daemon:

- **rx** — blocking `recv_from` in a loop, dispatch by message type.
- **timers** — wakes on a fixed tick, walks the peer table, fires rekey /
  keepalive / expiry.
- **main** — parses config, spawns the two above, joins.

Rules of the migration:

- The repo stays green at every step. Go and Rust coexist until the last Go file
  is deleted in slice 12.
- Go files are deleted only when the Rust replacement passes a port of that
  file's tests. Every Go test becomes a Rust test with the *same fixtures*.
- Each slice is a few hours of work, ends in something runnable or testable, and
  is one commit / one PR.

## Layout

Single crate, modules mirroring the Go packages, so the port maps 1:1:

```
Cargo.toml
src/
  lib.rs            # pub mod protocol; pub mod config;
  main.rs           # the daemon binary
  protocol/
    mod.rs
    keys.rs         # <- protocol/crypto.go (key half)
    kdf.rs          # <- protocol/crypto.go (hash/hkdf half)
    time.rs         # <- protocol/time.go
    message.rs      # <- protocol/types.go + protocol/serde.go
    noise.rs        # <- protocol/noise.go + protocol/peer.go
    cookie.rs       # <- protocol/cookie.go
    session.rs      # new: transport keys, nonces, replay window
    timers.rs       # new: rekey / keepalive / retry constants + state
  config.rs         # <- config/config.go + config.conf parsing
  daemon.rs         # <- main.go
```

Crates: `x25519-dalek`, `chacha20poly1305`, `blake2` (`Blake2s256`,
`Blake2sMac128`), `hmac`, `subtle`, `zeroize`, `rand`, `base64`, `thiserror`,
`tracing`. No runtime crate — `std::net` and `std::thread` only. Versions get
pinned in slice 1.

Note `blake2` gives keyed BLAKE2s directly — WireGuard's MAC1/MAC2 are *keyed
BLAKE2s-128*, not HMAC. Only the HKDF chain uses HMAC-BLAKE2s.

## Bugs in the Go code — fix during the port, don't carry them over

| Where | Bug |
|---|---|
| `noise.go` `ProcessInitiateHandshakeMessage` | Timestamp check is inverted: returns an error when `ts` is *newer* than the last seen. Should reject when **not** newer. |
| `noise.go` same fn | `aead.Open(pk[:], ...)` appends past the array instead of writing into it (`pk[:0]`), and the result is discarded — the decrypted static key is silently dropped and `pk` stays zero. |
| `noise.go` same fn | Static-static DH uses the *configured* `Remote.PublicKey` instead of the static key just decrypted from the message. Fine for one hardcoded peer, wrong as soon as there are several. |
| `noise.go` `ProcessInitiateHandshakeResponseMessage` | `t.RemoteID = t.Handshake.InitiatorIndex` — should be `message.Sender`. `InitiatorIndex` is only ever set on the responder. |
| `serde.go` `MessageHandshakeResponse::ToBytes` | Buffer sized with `MessageHandshakeCookieSize` (64) for a 92-byte message. Works only because `bytes.Buffer` grows. |
| `cookie.go` | `Checker` must be keyed with the **local** public key (we verify what others send *to us*); `Stamper` with the **remote** public key. `main.go` only ever builds a `Stamper`, so this is latent. |
| `cookie.go` `CheckMAC2` | Marked incorrect in a comment, and it is — MAC2 must be keyed by the cookie derived from the sender's source address (§5.4.7), not by the static `Mac2Key`. |

---

## M1 — Crypto core

### [S1](https://github.com/grambbledook/SimpleVPN/issues/1). Cargo scaffold
Add `Cargo.toml`, `src/lib.rs`, empty modules, `target/` to `.gitignore`, pin
dependency versions. `cargo test` runs (zero tests) and `cargo clippy` is clean.
Go untouched.

**Done when:** `cargo test && cargo clippy -- -D warnings` pass in CI-less local run.

### [S2](https://github.com/grambbledook/SimpleVPN/issues/2). Keys and DH — `protocol/keys.rs`
`PrivateKey` / `PublicKey` / `SharedSecret` newtypes, clamping, base64 parse and
render, `public_key()`, `shared_secret()`. `Zeroize` on the secret types.

**Tests (ported):** `Test_ECDH`, `Test_PrivateKey_ParsingAndDerivation` — with
the same `WEGlnZ…` / `pMo33…` pair, so a regression is visible against the Go
run.

### [S3](https://github.com/grambbledook/SimpleVPN/issues/3). Hash and KDF — `protocol/kdf.rs`
`hash(&[&[u8]])`, `hkdf_extract`, `hkdf_expand`, `kdf1/kdf2/kdf3`.

**Tests (ported):** the three KDF vectors in `crypto_test.go`, all of `t0`,`t1`,`t2`
(the Go test only ever asserts `t0` — assert all three).

**Delete:** `protocol/crypto.go`, `protocol/crypto_test.go`, `protocol/util.go`.

### [S4](https://github.com/grambbledook/SimpleVPN/issues/4). TAI64N — `protocol/time.rs`
`Tai64n::now()`, ordering. Fix the `2<<61` offset expression to the intended
`2^62 + 10` while keeping byte-identical output.

**Test:** known epoch → known 12 bytes; ordering across two calls.

**Delete:** `protocol/time.go`.

---

## M2 — Wire format

### [S5](https://github.com/grambbledook/SimpleVPN/issues/5). Messages and serde — `protocol/message.rs`
The four message types, `to_bytes` / `from_bytes`, little-endian, exact size
checks, explicit 3-byte reserved field rather than relying on `u32` type padding.

**Tests (ported):** all four `Test_MessageSerde_*` round-trips, plus a new
byte-exact decode of the captured 148-byte handshake-init blob from
`noise_test.go`, and a `to_bytes(from_bytes(x)) == x` check on it.

**Delete:** `protocol/types.go`, `protocol/serde.go`, `protocol/serde_test.go`.

---

## M3 — Handshake

### [S6](https://github.com/grambbledook/SimpleVPN/issues/6). Handshake, initiator + responder receive — `protocol/noise.rs`
`Peer`, `Tunnel`, `Handshake` state; `initiate_handshake()`,
`process_initiate_handshake()`. Fix bugs 1–3 above.

**Test (ported):** `TestTunnel_ProcessInitiateHandshakeMessage` — the recorded
real init message must decrypt, and (new, since the Go bug hid this) the
decrypted static key must equal the configured remote public key.

### [S7](https://github.com/grambbledook/SimpleVPN/issues/7). Response + transport key derivation
`create_handshake_response()`, `process_handshake_response()`,
`begin_symmetric_session()`. Fix bug 4.

**Test (ported):** `Test_Handshake` — full in-memory handshake, chain key and
hash agree at each stage, transport keys round-trip in both directions.

**Delete:** `protocol/noise.go`, `protocol/peer.go`, `protocol/noise_test.go`,
`protocol/constants.go`.

---

## M4 — Cookies

### [S8](https://github.com/grambbledook/SimpleVPN/issues/8). MAC1/MAC2 — `protocol/cookie.rs`
`Stamper` and `Checker`, keyed correctly (see bug table). MAC2 left as
"all-zero until we hold a cookie", which is the correct behaviour for an
un-loaded peer; the real MAC2 path lands in S16.

**Test (ported):** `Test_StamperMac1` against the same recorded response bytes.

**Delete:** `protocol/cookie.go`, `protocol/cookie_test.go`.
→ **The Go `protocol/` package is gone.**

---

## M5 — Transport data plane (new — no Go equivalent)

### [S9](https://github.com/grambbledook/SimpleVPN/issues/9). Session and nonces — `protocol/session.rs`
Send/receive keys as `ChaCha20Poly1305`, 64-bit counter in bytes 4..12 of the
12-byte nonce, encrypt/decrypt of transport payloads, padding to a 16-byte
boundary.

**Test:** round-trip, counter increments, a tampered tag fails, padding is
stripped.

### [S10](https://github.com/grambbledook/SimpleVPN/issues/10). Anti-replay window
Sliding bitmap window over the counter (match `wireguard-go`'s window size).

**Test:** in-order accept, duplicate reject, out-of-order-within-window accept,
too-old reject, behaviour at the window edge.

---

## M6 — Daemon

### [S11](https://github.com/grambbledook/SimpleVPN/issues/11). Config — `config.rs`
Parse the wg-style ini (`[Interface]` PrivateKey/ListenPort, `[Peer]`
PublicKey/Endpoint/AllowedIPs). Drop `[Peer] PrivateKey` from `config.conf` —
that field only exists because the current test setup holds both sides' keys;
keep the two-sided fixture in a separate `testdata/` file.

**Test:** parse the committed config, reject malformed keys.

**Delete:** `config/config.go`.

### [S12](https://github.com/grambbledook/SimpleVPN/issues/12). Blocking UDP daemon — `daemon.rs` + `main.rs`
`Device { socket: Arc<UdpSocket>, peers: Mutex<…> }`. Bind, blocking `recv_from`
loop on an rx thread, dispatch on message type, verify MAC1, drive the responder
side of the handshake, send the response, establish a session. Keep the lock
scope tight: decode and crypto happen outside the mutex, only table lookup and
state mutation happen inside it.

Keep the plaintext side behind a channel or a small `PacketSink` trait rather
than hardcoding what happens to a decrypted payload. Here the far end of that
boundary is the test harness; in M9 it becomes the TUN device.

**Test:** manual — point a real `wg` client at it and confirm the handshake
completes. Automated smoke test lands in S13.

**Delete:** `main.go`, `go.mod`, `go.sum`.
→ **Go is gone from the repo.**

### [S13](https://github.com/grambbledook/SimpleVPN/issues/13). Initiator role + loopback integration test
Dial a configured `Endpoint`, run the initiator side to completion.

**Test:** two daemon instances on `127.0.0.1`, different ports, each on its own
thread, complete a handshake and exchange an encrypted transport message. Bind
to port 0 and read back the assigned port so the test never collides. This is
the first end-to-end test and becomes the regression gate for everything after
it.

---

## M7 — Robustness

### [S14](https://github.com/grambbledook/SimpleVPN/issues/14). Timers
`REKEY_AFTER_TIME` 120s, `REJECT_AFTER_TIME` 180s, `REKEY_TIMEOUT` 5s,
`KEEPALIVE_TIMEOUT` 10s, `REKEY_AFTER_MESSAGES` 2^60, `REJECT_AFTER_MESSAGES`
2^64−2^13−1. Handshake retry, passive keepalive, session expiry, previous-keypair
retention during a rekey.

Driven by the timer thread on a fixed tick (250ms is plenty) rather than one
timer per event — one loop over the peer table, no per-peer scheduling.

**Test:** unit tests over an injectable clock — no sleeping in tests, and the
tick function is pure enough to call directly without spawning the thread.

### [S15](https://github.com/grambbledook/SimpleVPN/issues/15). Multi-peer
Peer table keyed by static public key, session table keyed by our local receiver
index. Route an incoming message by its receiver index; route an incoming init
by the static key decrypted from it (needs bug 3 fixed).

One `Mutex<HashMap<…>>` per table rather than a lock per peer — contention is
irrelevant at this scale and one lock ordering is one fewer thing to get wrong.

**Test:** two peers against one daemon, sessions stay independent.

### [S16](https://github.com/grambbledook/SimpleVPN/issues/16). Cookie reply
Emit type-3 cookie replies under load, verify MAC2 per §5.4.7, honour a received
cookie when stamping. Replaces the S8 placeholder.

**Test:** the §5.4.7 flow — reply is emitted, the stamped MAC2 verifies, a stale
cookie is rejected after 120s on the injectable clock.

---

## M8 — Ship

### [S17](https://github.com/grambbledook/SimpleVPN/issues/17). CLI, logging, docs
`clap` CLI (config path, log level, generate-keypair subcommand), `tracing`
output, fill in the README Build/Usage sections that currently say TBA, mark
WireGuard as supported-minus-TUN, and record the interop procedure against a
real `wg` peer.

---

## M9 — TUN device (optional, after M8)

Out of the original scope, kept as a follow-on. M1–M8 build the *encrypted* side
of the daemon — UDP in, UDP out, crypto in the middle. M9 adds the *plaintext*
side: real IP packets from a kernel TUN interface. Nothing in the handshake,
session or replay code changes.

Blocking IO pays off here. A TUN device is a file descriptor; it gets a third
thread and a blocking `read()`. Under an async runtime the fd would have to be
registered for readiness, which is the machinery this project is deliberately
avoiding.

**Prerequisite, and the reason this section exists now:** S12 must keep the
plaintext side behind a boundary — a channel or a small `PacketSink` trait —
rather than hardcoding what happens to a decrypted payload. With that boundary
M9 is additive; without it M9 starts by refactoring the daemon core.

Everything here needs `CAP_NET_ADMIN` (root, or `setcap cap_net_admin+ep` on the
binary), so unlike M1–M8 these tests cannot run unprivileged. Two peers on one
host need network namespaces, since each end wants its own TUN and routing
table. Verify `ip netns` works under WSL2 before committing to that test setup.

### [T1](https://github.com/grambbledook/SimpleVPN/issues/18). Open the TUN device
`/dev/net/tun`, `ioctl(TUNSETIFF)` with `IFF_TUN | IFF_NO_PI`, blocking
read/write on its own thread. Hand-rolled with `libc` — about 40 lines, and the
same reason this repo writes WireGuard instead of linking boringtun.

`IFF_TUN` gives raw IP packets rather than ethernet frames; `IFF_NO_PI` drops the
4-byte packet-info prefix that would otherwise lead every read.

**Test:** create the interface, `ip addr add` + `ip link set up`, ping the
subnet, and assert the bytes arriving are an ICMP echo request.

### [T2](https://github.com/grambbledook/SimpleVPN/issues/19). IP header parsing
Extract source and destination only — no full header validation.
IPv4: version nibble at byte 0, addresses at bytes 12..16 and 16..20.
IPv6: addresses at bytes 8..24 and 24..40.

**Test:** captured v4 and v6 packets, plus rejection of a truncated header and of
a version nibble that is neither 4 nor 6.

### [T3](https://github.com/grambbledook/SimpleVPN/issues/20). AllowedIPs trie
Prefix trie mapping an IP range to a peer, longest-prefix wins. Populated from
the `AllowedIPs` config field parsed back in S11.

**Test:** longest-prefix beats shorter, `0.0.0.0/0` catch-all, v4 and v6 kept
separate, no match returns nothing rather than a default peer.

### [T4](https://github.com/grambbledook/SimpleVPN/issues/21). Cryptokey routing — wire both directions
Outbound: tun read → dst lookup → peer session → encrypt → UDP send.
Inbound: UDP recv → decrypt → **check the inner source address against the
sending peer's AllowedIPs** → tun write.

That inbound check is the point of the milestone. A packet that decrypts
correctly can still be lying about where it came from; without the check any
authenticated peer can spoof any source address through the tunnel. This is what
separates WireGuard's model from "authenticate, then forward whatever arrives".

**Test:** two daemons in separate network namespaces, ping across the tunnel. Then
a negative test — a peer sends a packet whose inner source is outside its own
AllowedIPs, and it is dropped.

### [T5](https://github.com/grambbledook/SimpleVPN/issues/22). MTU and setup
`Address =` and `MTU =` config fields, default MTU 1420, and a wg-quick-style
setup script.

1420 is not arbitrary: 1500 − 48 (outer IPv6 + UDP) − 32 (16-byte transport
header + 16-byte Poly1305 tag) = 1420. Deriving it is part of the exercise.

**Test:** a payload at exactly the MTU passes; one over it is handled rather than
silently truncated.
