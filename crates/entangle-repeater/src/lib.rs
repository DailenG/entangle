//! Blind WebSocket relay for end-to-end Entangle links.

pub mod client;
pub mod invite;
pub mod server;
pub mod store;
pub mod wire;

pub use client::{connect, RepeaterClient, RepeaterStream};
pub use invite::{decode, encode, Invite};
pub use server::{serve, ServerConfig};
pub use store::{Device, Devices, InviteRecord, Invites, Store};

#[cfg(test)]
mod integration_tests;
