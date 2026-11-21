//! nearcast: a Quick Share (Nearby Share) implementation for Linux.
//!
//! Layers, bottom to top:
//! - [`wire`]: length-prefixed frames, plain or inside the UKEY2 secure channel
//! - [`ukey2`]: the UKEY2 handshake that keys the secure channel
//! - [`connection`]: Nearby Connections (payloads, keep-alives, disconnection)
//! - [`upgrade`]: moving a connection to a faster medium
//! - [`share`]: Nearby Sharing (introduction, consent, files and text)
//! - [`mdns`]: discovery and advertising on the local network
//! - [`daemon`] / [`ipc`]: the per-user daemon and its client protocol

pub mod bluetooth;
pub mod connection;
pub mod daemon;
pub mod endpoint;
pub mod ipc;
pub mod mdns;
pub mod mediums;
pub mod netd;
pub mod proto;
pub mod share;
pub mod ukey2;
pub mod upgrade;
pub mod wire;
