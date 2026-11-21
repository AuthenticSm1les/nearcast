//! Client protocol between nearcastd and its front ends (CLI, GUI).
//!
//! A Unix socket in the user's runtime directory carrying JSON, one message
//! per line. Clients send [`Request`]s; the daemon answers each with `ok`,
//! `error`, `status` or `started`, and streams events (`device_found`,
//! `device_lost`, `transfer`) to clients that asked to watch or discover.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use crate::endpoint::DeviceType;
use crate::share::{FileEntry, TextKind, WifiSecurity};

pub fn socket_path() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", nix::unistd::getuid())));
    dir.join("nearcast.sock")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Daemon settings and all transfers.
    Status,
    /// Look for devices until this client disconnects; streams events.
    Discover,
    /// Stream all events.
    Watch,
    /// Share files and/or text with a device (ID or name); streams events.
    Send {
        to: String,
        #[serde(default)]
        files: Vec<PathBuf>,
        #[serde(default)]
        text: Option<String>,
    },
    Accept { id: String },
    Reject { id: String },
    Cancel { id: String },
    SetVisible { visible: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub route: Route,
}

/// How a device can be reached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "medium", content = "addr", rename_all = "snake_case")]
pub enum Route {
    WifiLan(SocketAddr),
    /// Bluetooth Classic address.
    Bluetooth(String),
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Route::WifiLan(a) => write!(f, "wifi {a}"),
            Route::Bluetooth(a) => write!(f, "bluetooth {a}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Connecting,
    /// Outgoing: waiting for the receiver to accept.
    WaitingForAccept,
    /// Incoming: waiting for the user to accept or reject.
    AwaitingDecision,
    Transferring,
    Finished,
    Rejected,
    Cancelled,
    Failed,
}

impl TransferState {
    pub fn is_final(self) -> bool {
        matches!(self, Self::Finished | Self::Rejected | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextInfo {
    pub kind: TextKind,
    /// Preview offered before accepting.
    pub title: String,
    /// The full text, once received.
    pub content: Option<String>,
}

/// A Wi-Fi network shared with us. nearcast doesn't add it to the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInfo {
    pub ssid: String,
    pub security: WifiSecurity,
    /// The password, once received (empty for an open network).
    pub password: Option<String>,
    /// Whether the network hides its name.
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub direction: Direction,
    pub peer: String,
    pub peer_type: DeviceType,
    pub state: TransferState,
    pub pin: Option<String>,
    pub files: Vec<FileEntry>,
    pub texts: Vec<TextInfo>,
    /// Wi-Fi networks offered (incoming only).
    #[serde(default)]
    pub wifi: Vec<WifiInfo>,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Where received files were saved.
    pub saved: Vec<PathBuf>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Ok,
    Error { message: String },
    Status {
        name: String,
        endpoint_id: String,
        visible: bool,
        port: u16,
        download_dir: PathBuf,
        transfers: Vec<Transfer>,
    },
    Started { id: String },
    DeviceFound { device: Device },
    DeviceLost { id: String },
    Transfer { transfer: Transfer },
}

/// A connection to the daemon.
pub struct Client {
    lines: Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
}

impl Client {
    pub async fn connect() -> anyhow::Result<Self> {
        let path = socket_path();
        let stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("can't reach nearcastd at {} (is it running?)", path.display()))?;
        let (r, w) = stream.into_split();
        Ok(Self { lines: BufReader::new(r).lines(), writer: w })
    }

    pub async fn send(&mut self, req: &Request) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        self.writer.write_all(&line).await?;
        Ok(())
    }

    /// Next message, or None when the daemon closed the connection.
    pub async fn next(&mut self) -> anyhow::Result<Option<Message>> {
        match self.lines.next_line().await? {
            Some(l) => Ok(Some(serde_json::from_str(&l).context("bad message from nearcastd")?)),
            None => Ok(None),
        }
    }

    /// Sends a request and returns its reply, skipping events.
    pub async fn call(&mut self, req: &Request) -> anyhow::Result<Message> {
        self.send(req).await?;
        loop {
            match self.next().await?.context("nearcastd closed the connection")? {
                Message::DeviceFound { .. } | Message::DeviceLost { .. } | Message::Transfer { .. } => {}
                Message::Error { message } => anyhow::bail!(message),
                m => return Ok(m),
            }
        }
    }
}
