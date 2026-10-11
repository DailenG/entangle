# Architecture

Entangle keeps discovery independent from encrypted transport. The binary
composes the protocol and platform crates.

## Crates and dependency rule

| Crate | Responsibility |
| --- | --- |
| `entangle-core` | Particle IDs, manifests, payload kinds, safe names |
| `entangle-resonance` | mDNS advertisement, browsing, and discovery events |
| `entangle-transport` | Noise XXpsk3 secure streams and encrypted message framing |
| `entangle-link` | Encrypted Hello, sync negotiation, and bounded payload streams |
| `entangle-mcp` | MCP JSON-RPC over stdio and tool backend abstraction |
| `entangle` | CLI and `Particle` orchestration that composes the libraries |

`entangle-resonance` has no dependency on transport. It publishes the particle
ID, protocol, name, version, optional context, and optional public pairing
group (`grp`) in mDNS TXT records. The pairing key itself is never advertised.

## Pairing and link

Both devices must use the same 32-byte pairing key. Its human-entered code is
RFC 4648 Base32 without padding, prefixed with `ENT1-` and grouped in
four-character chunks. The public group ID is the first 8 hex characters of
`SHA-256("entangle-pair-group-v1" || key)`; the Noise PSK is
`SHA-256("entangle-pair-psk-v1" || key)`.
The pairing key is stored at `<data_root>/pairing.key`; each persistent
particle's 32-byte Noise static private key is stored as 64 lowercase hex
characters at `<data_root>/noise_static.key`. Ephemeral identities keep their
static key in memory only. On Unix, key files are mode 0600.

Each TCP connection begins with a three-message
`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake. JSON control frames are
individual encrypted Noise messages, bounded to 60 KiB. An accepted sync
streams exactly the declared payload size in encrypted messages; each receive
chunk has a five-second idle timeout. The receiver verifies the byte count and
SHA-256 before adding the item to its inbox.

## Human peer approval

Protocol version 3 separates authentication from authorization. A valid
pairing-key Noise handshake places a previously unapproved peer in `pending`;
neither side may sync until its local operator approves that peer. Approved
particle IDs are pinned to their Noise static public keys. Decisions live in
`<data_root>/peers/trust.json`; node-owned commit/reveal state is kept in
`<data_root>/peers/verify/<particle_id>.json`. Unix directories and files use
private permissions, and writes are atomic.

The lower static public key is the committer and the higher is the revealer.
The committer first commits to a random nonce with
`SHA-256("entangle-sas-commit-v1" || nonce_c || key_c || key_r)`. Only after
the revealer's nonce is received does the committer reveal its nonce. Both
derive three 6-bit emoji indices from
`SHA-256("entangle-sas-v1" || version || key_c || key_r || nonce_c || nonce_r)`.
Commit-then-reveal prevents either peer from grinding its nonce in response to
the other's; an active attacker who already knows the pairing key has a
1-in-262,144 chance of making all three displayed emoji match by chance.
Operators compare the set out of band before approving.

Approval is local to each machine. `peer verify` displays this machine's card;
the human uses `peer approve` on both devices. Agents may inspect `peer list`
and `peer emoji`, but approval, denial, revocation, and forgetting are
human-only operations. An ephemeral identity never reads or writes the trust
store and cannot persist peer approval.

## Execution flow

```mermaid
sequenceDiagram
    participant A as Particle A / MCP client
    participant MD as mDNS
    participant B as Particle B
    A->>MD: advertise public group ID + browse
    MD-->>A: Resonance event for B
    A->>B: Noise XXpsk3 handshake
    A->>B: encrypted Hello(manifest)
    B-->>A: encrypted Hello(manifest)
    A->>B: encrypted SyncOffer(from, size, hash)
    B-->>A: encrypted SyncAccept
    A->>B: encrypted payload chunks
    B->>B: verify size/hash; persist inbox metadata
    B-->>A: encrypted SyncComplete
    B-->>A: MCP notification
```

The protocol is not wire-compatible with 0.1.x or 0.2.x; upgrade all devices
before pairing. MCP continues to use JSON-RPC 2.0 with newline-delimited
messages on stdio. Logs go to stderr; stdout belongs exclusively to MCP.

## Security model and limitations

Noise encrypts and authenticates the link using the pairing-derived PSK.
Approved static keys are pinned to particle IDs across restarts. A first
contact remains pending until a human compares and approves the SAS. The
optional `--context` value is a project label, not an authorization boundary.
It is not post-quantum secure beyond the PSK mixing.
Pairing codes are secrets: transfer them only between humans, never through
Entangle or to an agent. Keep the key file private and use only devices trusted
with the same pairing key.

Further work is tracked in [issue #10](https://github.com/DailenG/entangle/issues/10).

## Quantum Repeater (preview)

The Quantum Repeater is a blind WebSocket relay for links between networks
that cannot reach one another directly. A client pins the repeater's static
key and authenticates its connection with Noise `IK`. After enrollment, each
live session declares its current public pairing-group ID; that ID is
ephemeral routing metadata, not an enrollment property or a persisted device
field.

Each Noise handshake or transport message occupies one WebSocket binary
message. Session plaintext has a `type:u8 | stream:u32 BE | body` header and
uses `LIST`, `OPEN`, `INCOMING`, `DATA`, `CLOSE`, `OPEN_FAIL`, `PING`, and
`PONG` frames; DATA bodies are limited to 60 KiB. Client stream IDs have the
high bit clear, while repeater-assigned incoming IDs have it set. The repeater
routes only between enrolled live sessions that declare the same group,
applies session and stream limits, and closes removed or revoked devices when
the host reloads its device file. Invite secrets are single-use and stored
only as SHA-256 digests.

The peer-to-peer Noise `XXpsk3` session remains end-to-end. The repeater
forwards its encrypted bytes without inspecting or logging them: it cannot
see particle names, pairing keys, SAS values, or sync content. It can see
static device public keys, declared group IDs, connection timing, and
traffic sizes; group IDs are public routing identifiers, not an authorization
boundary. The pairing-derived PSK and local SAS approval remain the
end-to-end security boundary. Repeater use is preview-only until node
integration is delivered.
