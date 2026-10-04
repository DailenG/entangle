# Architecture

Entangle has a strict crate direction: protocol/data libraries remain
independent and only the binary composes them.

## Crates and dependency rule

| Crate | Responsibility |
| --- | --- |
| `entangle-core` | Particle IDs, manifests, payload kinds, relay tickets, safe names |
| `entangle-resonance` | mDNS advertisement, browsing, and discovery events |
| `entangle-transport` | croc executable, process-owned relay, send/receive handles |
| `entangle-link` | TCP NDJSON control protocol, Hello, sync negotiation |
| `entangle-mcp` | MCP JSON-RPC over stdio and tool backend abstraction |
| `entangle` | CLI and `Particle` orchestration that composes the libraries |

`entangle-resonance`, `entangle-transport`, and `entangle-link` depend on at
most `entangle-core`. Transport never depends on discovery or link, and
discovery never depends on transfer code. `entangle-mcp` depends on no other
Entangle crate. Only the `entangle` binary depends on all of these modules. The
orchestrator is the sole location that associates a discovered peer with a
fresh croc secret and local relay ticket.

## Execution flow

```mermaid
sequenceDiagram
    participant A as Particle A / MCP client
    participant MD as mDNS
    participant B as Particle B
    participant R as A's private croc relay
    A->>MD: advertise particle + browse
    MD-->>A: Resonance event for B
    A->>B: TCP Hello(manifest)
    B-->>A: TCP Hello(manifest)
    A->>R: start relay on configured local ports
    A->>B: SyncOffer(ticket, one-time secret, hash, size)
    B-->>A: SyncAccept
    B->>R: croc receive using secret from private ticket
    A->>R: croc send using secret from private ticket
    R-->>B: encrypted payload
    B->>B: verify filename, size, SHA-256; index inbox
    B-->>A: SyncComplete(verified SHA-256)
    B-->>A: MCP notifications/message
    A-->>A: MCP tool returns delivered result
```

## Wire protocol

The mDNS service is `_entangle._tcp.local.`. TXT records contain only `id`,
`proto`, `name`, optional `ctx`, and `ver`; the full manifest is sent over the
link because DNS TXT records are size-limited. The manifest includes accepted
payload kinds, tool names, context, link port, and payload limit.

Link control messages are UTF-8 JSON objects terminated by a newline, one
frame per short-lived TCP connection. The maximum frame is 64 KiB. Hello
exchanges manifests; SyncOffer carries the transfer ID, sanitized filename,
kind, size, SHA-256, optional label, relay ticket, and one-time secret. The
receiver accepts or rejects, then sends SyncComplete only after checking the
received bytes. SyncFailed identifies a failed receive. Connections are
bounded by the caller's operation timeout.

MCP uses JSON-RPC 2.0 with newline-delimited messages on stdio. Logs are sent
to stderr; stdout belongs exclusively to MCP. Tool schemas in
`schemas/mcp-tools.json` are the source of truth.

## Security model and limitations

Payload bytes travel using croc's encrypted transfer protocol through a relay
owned by the sender on the local network. Entangle explicitly supplies that
relay's host, port, and password, avoiding the public relay and public fallback.
The one-time transfer secret is never put in process arguments; it is passed to
croc through `CROC_SECRET`.

**The current TCP control channel is plaintext.** A LAN observer able to sniff
the SyncOffer can see the one-time secret and relay password. croc's PAKE and
end-to-end payload encryption protect payload contents from parties that do
not see the offer; they do not hide the offer from a LAN sniffer. The first
version does not authenticate peer identities beyond possession of a live
particle connection and does not protect the manifest/control messages.

Use trusted local networks and short-lived secrets. A future protocol version
should add Noise or TLS-PSK pairing for the control link. Other limits include
multicast dependence for automatic discovery, a process-local inbox index,
and no resume protocol for interrupted transfers.
