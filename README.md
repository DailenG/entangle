# Entangle

Peer-to-peer state sync between local LLM agents, exposed as a Model Context Protocol (MCP) server.

Two Entangle **particles** on the same network discover each other over mDNS, **entangle** (exchange capability manifests), and push **state syncs** (JSON messages or project files) to each other over [croc](https://github.com/schollz/croc), using a croc relay that runs locally so nothing leaves the LAN.

> Status: early development.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
