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

The 0.2 protocol is not wire-compatible with 0.1.x; upgrade both devices
before pairing. MCP continues to use JSON-RPC 2.0 with newline-delimited
messages on stdio. Logs go to stderr; stdout belongs exclusively to MCP.

## Security model and limitations

Noise encrypts and authenticates the link using the pairing-derived PSK, and
each peer's static public key is bound to its claimed particle ID for the
current process. This release does not provide persistent peer pinning across
restarts or peer approval. It is not post-quantum secure beyond the PSK mixing.
The optional `--context` value is a project label, not an authorization
boundary; pairing is the access control.
Pairing codes are secrets: transfer them only between humans, never through
Entangle or to an agent. Keep the key file private and use only devices trusted
with the same pairing key.

Further work is tracked in [issue #10](https://github.com/DailenG/entangle/issues/10).
