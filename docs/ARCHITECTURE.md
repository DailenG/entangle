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
ID, protocol, name, version, optional context, and public group IDs (`grp`) in
mDNS TXT records. The `grp` value is a sorted, comma-separated list of zero to
eight eight-hex group IDs. Group keys are never advertised.

## Groups and link

Each machine can belong to up to eight groups stored at
`<data_root>/groups/<id>/{key,meta.json,members.json,keys.json,updates.json}`.
The `key` file contains the current 32-byte group key as lowercase hex;
`meta.json` stores the group name, epoch, admin identity and signing key, and
the current revocation set. `members.json` maps particle IDs to names, Noise
static public keys, and signing public keys. `keys.json` retains up to 16 prior
epoch keys and `updates.json` retains the corresponding signed update chain.
Files and directories use private permissions. The group ID is the first four
bytes of
`SHA-256("entangle-group-id-v1" || key)`, encoded as eight lowercase hex
characters at creation; it remains stable when the key rotates. Its Noise PSK is
`SHA-256("entangle-group-psk-v1" || key)`.

Group admins sign updates with an Ed25519 key derived from the particle's
static private key. Updates form a contiguous epoch chain and carry the new
group key, admin, and revocation set. A member verifies each signature against
the current admin key before applying the next epoch. Updates can be relayed by
any current member; a removed member cannot pass current membership checks.

Protocol version 5 binds each link to a group and epoch. Before the Noise
handshake, the initiator writes a 13-byte preface: `ENTG`, preface version `2`,
the four group-ID bytes, and the requested epoch as a big-endian `u32`.
Responders negotiate retained epochs with plaintext acknowledgements; a peer
outside the retained-key window is rejected before Noise. Both sides use the
unchanged
`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` pattern, the selected group's PSK at
position 3, and the prologue
`b"entangle-link-v5" || group_id_bytes || epoch_be`. A responder rejects malformed
prefaces and IDs for groups it does not have. Persistent particles store their
32-byte Noise static private key as 64 lowercase hex characters at
`<data_root>/noise_static.key`; ephemeral identities keep their static key in
memory only.

Each link stream performs a three-message Noise handshake. JSON control frames
are individual encrypted Noise messages, bounded to 60 KiB. An accepted sync
streams exactly the declared payload size in encrypted messages; each receive
chunk has a five-second idle timeout. The receiver verifies the byte count and
SHA-256 before adding the item to its inbox.

Group onboarding uses a one-time, three-word SPAKE2 code. The inviter
advertises a short-lived nameplate with mDNS; `--via <host:port>` bypasses
discovery, and failed confirmation closes the invite. Invites expire after ten
minutes and can be limited with `--count`. The inviter should stay online
briefly after onboarding: members are propagated by one-hop introductions,
vouched for by the member who added them.

## Membership trust

The authenticated group is the trust boundary. A link's Hello is accepted
only when its particle ID is present in that group's `members.json` and the
stored member static key matches the remote Noise-authenticated static key.
Offers and incoming payloads use the same membership and key-binding check.
There is no separate peer-approval or verification state.

After a successful Hello, peers exchange introductions for group members
vouched for by the sender. A receiver accepts an introduction only over an
authenticated link for that group, from a group member, and when every
introduced record names that sender as `added_by`. This is one hop, not a
transitive trust assertion; an inviter should remain online briefly so
existing members can learn about new joiners.

## Execution flow

```mermaid
sequenceDiagram
    participant A as Particle A / MCP client
    participant MD as mDNS
    participant B as Particle B
    A->>MD: advertise public group IDs + browse
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

Protocol version 5 is not wire-compatible with earlier versions; all devices
must use version 5 to communicate. MCP continues to use JSON-RPC 2.0 with
newline-delimited messages on stdio. Logs go to stderr; stdout belongs
exclusively to MCP.

## Security model and limitations

Noise encrypts and authenticates each link using the selected group's
derived PSK. A peer is trusted only when the link's group membership binds its
particle ID to the authenticated static public key. Group keys must be kept
private and shared only with the devices intended to join that group. The
optional `--context` value is a project label, not an authorization boundary.
The protocol is not post-quantum secure.

Further work is tracked in [issue #10](https://github.com/DailenG/entangle/issues/10).

## Quantum Repeater

The Quantum Repeater is a blind WebSocket relay for links between networks
that cannot reach one another directly. A client pins the repeater's static
key and authenticates its connection with Noise `IK`. After enrollment, each
live session declares its current public group ID; that ID is
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

The node tries direct TCP first, then uses a repeater tunnel for peers in the
same live directory. Relayed Hello metadata is never treated as a real socket
address: it cannot replace or erase mDNS-learned addresses, and the
`0.0.0.0:0` serving placeholder is never advertised or dialed. Relay-only
mode removes the TCP listener and disables mDNS.

The peer-to-peer Noise `XXpsk3` session remains end-to-end. The repeater
forwards its encrypted bytes without inspecting or logging them: it cannot
see particle names, group keys, repeater-enrollment SAS values, or sync
content. It can see static device public keys, declared group IDs, connection
timing, and traffic sizes; group IDs are public routing identifiers, not an
authorization boundary. The group-derived PSK and membership-bound static key
are the end-to-end security boundary.

Devices can request repeater enrollment at `{path}/request` without knowing the
repeater key: Noise `XX` authenticates the exchange. The host operator
approves after comparing the device and repeater fingerprints shown on both
the device and the host. The protocol still runs the commit/reveal SAS
exchange for wire compatibility, but the CLI no longer displays it. Pending
requests and device decisions use single-writer atomic files; the repeater
alone writes `requests.json`, while the host CLI updates the device allowlist.

### Known limits (v1)

One slow stream can delay other streams on the same session (head-of-line
blocking). Per-stream credit windows are a follow-up.
