//! Nearby Sharing on top of a connection: paired-key exchange, introduction,
//! consent, then file and text payloads.
//!
//! We run in "everyone" mode: we have no Google account certificates, so the
//! paired-key frames carry random data and we answer PairedKeyResult UNABLE,
//! as Nearby Sharing does for unknown devices.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use prost::Message;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::connection::{Connection, Event, PayloadSender, Remote};
use crate::endpoint::{decode_endpoint_info, DeviceType};
use crate::proto::connections::payload_transfer_frame::payload_header::PayloadType;
use crate::proto::sharing::connection_response_frame::Status;
use crate::proto::sharing::{
    file_metadata, frame, paired_key_result_frame, text_metadata, v1_frame, wifi_credentials_metadata,
    ConnectionResponseFrame, FileMetadata, Frame, IntroductionFrame, PairedKeyEncryptionFrame,
    PairedKeyResultFrame, TextMetadata, V1Frame, WifiCredentials,
};

/// How long we wait for the receiver to hang up after the last payload.
const FINISH_TIMEOUT: Duration = Duration::from_secs(60);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
const TEXT_TITLE_LEN: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TextKind {
    Text,
    Url,
    Address,
    PhoneNumber,
}

/// How a shared Wi-Fi network is secured.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WifiSecurity {
    Unknown,
    Open,
    WpaPsk,
    Wep,
}

/// A text offered in an introduction, before it arrives.
#[derive(Debug, Clone, PartialEq)]
pub struct OfferedText {
    pub kind: TextKind,
    /// The preview the sender put in the introduction.
    pub title: String,
}

/// A Wi-Fi network offered in an introduction, before its password arrives.
#[derive(Debug, Clone, PartialEq)]
pub struct OfferedWifi {
    pub ssid: String,
    pub security: WifiSecurity,
}

/// A received Wi-Fi network. nearcast only reports it; adding it to the
/// system's networks is up to the user or a front end.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedWifi {
    pub password: String,
    pub hidden: bool,
}

/// Progress reports from a running transfer.
#[derive(Debug, Clone)]
pub enum Update {
    /// Outgoing: connected; both sides now show this PIN.
    Connected { pin: String },
    /// Outgoing: waiting for the receiver to accept.
    WaitingForAccept,
    /// Incoming: the sender wants to share; waiting for our decision.
    Incoming {
        peer_name: String,
        peer_type: DeviceType,
        pin: String,
        files: Vec<FileEntry>,
        texts: Vec<OfferedText>,
        wifi: Vec<OfferedWifi>,
    },
    Transferring,
    Progress { done: u64, total: u64 },
    /// `texts` and `wifi` are in the order the introduction offered them.
    Finished { saved: Vec<PathBuf>, texts: Vec<String>, wifi: Vec<ReceivedWifi> },
    Rejected,
    Cancelled { by_peer: bool },
    Failed(String),
}

pub struct Control {
    pub cancel: CancellationToken,
    pub updates: mpsc::UnboundedSender<Update>,
    /// Where connections that linger after a reject or cancel run, so the
    /// daemon can let them finish before it exits.
    pub lingers: TaskTracker,
}

impl Control {
    fn update(&self, u: Update) {
        let _ = self.updates.send(u);
    }
}

/// Why a transfer stopped early.
#[derive(Debug)]
enum Stop {
    LocalCancel,
    PeerCancel,
    Rejected,
    /// We answered the introduction with something other than ACCEPT or
    /// REJECT (unsupported content, no space); the message says why.
    Refused(String),
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Stop::Refused(why) => f.write_str(why),
            s => write!(f, "{s:?}"),
        }
    }
}

/// How long to keep the connection open after rejecting a share, and after
/// cancelling one, before hanging up (Chrome's kIncomingRejectionDelay and
/// kInitiatorCancelDelay). Android handles a disconnection ahead of frames it
/// has received but not yet processed, so closing straight after the REJECT
/// response or the CANCEL frame makes the phone report a failed connection
/// instead of a declined or cancelled share. The connection closes sooner if
/// the peer hangs up first.
/// Received file data is written in blocks of this size, so a write to
/// disk (a blocking-pool task in tokio) covers several chunks.
const RECEIVE_BUFFER: usize = 2 * 1024 * 1024;
const REJECT_LINGER: Duration = Duration::from_secs(2);
const CANCEL_LINGER: Duration = Duration::from_secs(5);
impl std::error::Error for Stop {}

fn final_update(r: anyhow::Result<Update>) -> Update {
    match r {
        Ok(u) => u,
        Err(e) => match e.downcast_ref::<Stop>() {
            Some(Stop::LocalCancel) => Update::Cancelled { by_peer: false },
            Some(Stop::PeerCancel) => Update::Cancelled { by_peer: true },
            Some(Stop::Rejected) => Update::Rejected,
            Some(Stop::Refused(why)) => Update::Failed(why.clone()),
            None => Update::Failed(format!("{e:#}")),
        },
    }
}

fn sharing_frame(t: v1_frame::FrameType, f: impl FnOnce(&mut V1Frame)) -> Vec<u8> {
    let mut v1 = V1Frame { r#type: Some(t.into()), ..Default::default() };
    f(&mut v1);
    Frame { version: Some(frame::Version::V1.into()), v1: Some(v1) }.encode_to_vec()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    rand::rng().fill_bytes(&mut v);
    v
}

async fn send_paired_key_encryption(s: &PayloadSender) -> anyhow::Result<()> {
    s.send_bytes(sharing_frame(v1_frame::FrameType::PairedKeyEncryption, |f| {
        f.paired_key_encryption = Some(PairedKeyEncryptionFrame {
            secret_id_hash: Some(random_bytes(6)),
            signed_data: Some(random_bytes(72)),
            ..Default::default()
        })
    }))
    .await
}

async fn send_response(s: &PayloadSender, status: Status) -> anyhow::Result<()> {
    s.send_bytes(sharing_frame(v1_frame::FrameType::Response, |f| {
        f.connection_response = Some(ConnectionResponseFrame { status: Some(status.into()) })
    }))
    .await
}

async fn send_cancel(s: &PayloadSender) -> anyhow::Result<()> {
    s.send_bytes(sharing_frame(v1_frame::FrameType::Cancel, |_| {})).await
}

/// Next sharing frame from the peer.
async fn next_frame(conn: &mut Connection, cancel: &CancellationToken) -> anyhow::Result<V1Frame> {
    let ev = tokio::select! {
        _ = cancel.cancelled() => return Err(Stop::LocalCancel.into()),
        ev = conn.recv() => ev?,
    };
    match ev {
        Event::Bytes { data, .. } => {
            let v1 = Frame::decode(&*data)?.v1.context("sharing frame without v1")?;
            if v1.r#type() == v1_frame::FrameType::Cancel {
                return Err(Stop::PeerCancel.into());
            }
            Ok(v1)
        }
        Event::Disconnected => bail!("the other device disconnected"),
        Event::PayloadCanceled(_) => Err(Stop::PeerCancel.into()),
        Event::FileChunk { .. } => bail!("unexpected file data"),
    }
}

async fn expect_frame(
    conn: &mut Connection,
    cancel: &CancellationToken,
    t: v1_frame::FrameType,
) -> anyhow::Result<V1Frame> {
    let f = next_frame(conn, cancel).await?;
    if f.r#type() != t {
        bail!("expected {t:?}, got {:?}", f.r#type());
    }
    Ok(f)
}

/// Paired-key exchange, identical on both sides.
async fn exchange_paired_keys(conn: &mut Connection, cancel: &CancellationToken) -> anyhow::Result<()> {
    let s = conn.sender();
    send_paired_key_encryption(&s).await?;
    expect_frame(conn, cancel, v1_frame::FrameType::PairedKeyEncryption).await?;
    s.send_bytes(sharing_frame(v1_frame::FrameType::PairedKeyResult, |f| {
        f.paired_key_result = Some(PairedKeyResultFrame {
            status: Some(paired_key_result_frame::Status::Unable.into()),
        })
    }))
    .await?;
    expect_frame(conn, cancel, v1_frame::FrameType::PairedKeyResult).await?;
    Ok(())
}

/// Waits up to `max` for the peer to hang up, reading (and dropping) what it
/// still sends, then closes.
async fn close_after(mut conn: Connection, max: Duration) {
    let _ = tokio::time::timeout(max, async {
        while !matches!(conn.recv().await, Ok(Event::Disconnected) | Err(_)) {}
    })
    .await;
    conn.close().await;
}

/// Sends a cancel, then closes in the background after giving the peer time
/// to act on it, ignoring errors (the peer may already be gone).
async fn abort(conn: Connection, lingers: &TaskTracker) {
    let _ = send_cancel(&conn.sender()).await;
    lingers.spawn(close_after(conn, CANCEL_LINGER));
}

struct Progress {
    done: u64,
    total: u64,
    last: Instant,
}

impl Progress {
    fn new(total: u64) -> Self {
        Self { done: 0, total, last: Instant::now() }
    }

    fn add(&mut self, n: u64, ctl: &Control) {
        self.done += n;
        if self.done == self.total || self.last.elapsed() >= PROGRESS_INTERVAL {
            self.last = Instant::now();
            ctl.update(Update::Progress { done: self.done, total: self.total });
        }
    }
}

// ---------------------------------------------------------------- sending

pub struct Outgoing {
    /// Opens the connection (over Wi-Fi or Bluetooth).
    pub connect: std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Connection>> + Send>>,
    pub files: Vec<PathBuf>,
    pub text: Option<String>,
}

struct OutFile {
    meta: FileMetadata,
    file: tokio::fs::File,
}

fn file_kind(path: &Path, mime: &str) -> file_metadata::Type {
    if mime.starts_with("image/") {
        file_metadata::Type::Image
    } else if mime.starts_with("video/") {
        file_metadata::Type::Video
    } else if mime.starts_with("audio/") {
        file_metadata::Type::Audio
    } else if path.extension().is_some_and(|e| e == "apk") {
        file_metadata::Type::App
    } else {
        file_metadata::Type::Unknown
    }
}

async fn open_outgoing(path: &Path) -> anyhow::Result<OutFile> {
    let file = tokio::fs::File::open(path).await.with_context(|| format!("opening {}", path.display()))?;
    let md = file.metadata().await?;
    if !md.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no usable file name", path.display()))?
        .to_owned();
    let mime = mime_guess::from_path(path).first_or_octet_stream().to_string();
    let mut rng = rand::rng();
    Ok(OutFile {
        meta: FileMetadata {
            name: Some(name),
            r#type: Some(file_kind(path, &mime).into()),
            payload_id: Some(rng.random()),
            size: Some(md.len() as i64),
            mime_type: Some(mime),
            id: Some(rng.random()),
        },
        file,
    })
}

pub fn text_kind(text: &str) -> TextKind {
    let t = text.trim();
    let is_url = (t.starts_with("https://") || t.starts_with("http://")) && !t.contains(char::is_whitespace);
    if is_url { TextKind::Url } else { TextKind::Text }
}

fn text_title(text: &str) -> String {
    match text.char_indices().nth(TEXT_TITLE_LEN) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_owned(),
    }
}

pub async fn send(req: Outgoing, ctl: Control) {
    let r = run_send(req, &ctl).await;
    ctl.update(final_update(r));
}

async fn run_send(req: Outgoing, ctl: &Control) -> anyhow::Result<Update> {
    if req.files.is_empty() && req.text.is_none() {
        bail!("nothing to send");
    }
    let mut files = Vec::with_capacity(req.files.len());
    for p in &req.files {
        files.push(open_outgoing(p).await?);
    }
    let text = req.text.map(|t| {
        let kind = text_kind(&t);
        let meta = TextMetadata {
            text_title: Some(text_title(&t)),
            r#type: Some(match kind {
                TextKind::Url => text_metadata::Type::Url,
                _ => text_metadata::Type::Text,
            }
            .into()),
            payload_id: Some(rand::rng().random()),
            size: Some(t.len() as i64),
            id: Some(rand::rng().random()),
        };
        (meta, t)
    });

    let mut conn = tokio::select! {
        _ = ctl.cancel.cancelled() => return Err(Stop::LocalCancel.into()),
        c = req.connect => c?,
    };
    ctl.update(Update::Connected { pin: conn.pin().to_owned() });

    match send_session(&mut conn, files, text, ctl).await {
        Ok(()) => {
            // The receiver hangs up once it has everything.
            let _ = tokio::time::timeout(FINISH_TIMEOUT, async {
                while !matches!(conn.recv().await, Ok(Event::Disconnected) | Err(_)) {}
            })
            .await;
            conn.close().await;
            Ok(Update::Finished { saved: Vec::new(), texts: Vec::new(), wifi: Vec::new() })
        }
        Err(e) => {
            match e.downcast_ref::<Stop>() {
                Some(Stop::LocalCancel) => abort(conn, &ctl.lingers).await,
                _ => conn.close().await,
            }
            Err(e)
        }
    }
}

async fn send_session(
    conn: &mut Connection,
    mut files: Vec<OutFile>,
    text: Option<(TextMetadata, String)>,
    ctl: &Control,
) -> anyhow::Result<()> {
    exchange_paired_keys(conn, &ctl.cancel).await?;
    let s = conn.sender();
    s.send_bytes(sharing_frame(v1_frame::FrameType::Introduction, |f| {
        f.introduction = Some(IntroductionFrame {
            file_metadata: files.iter().map(|f| f.meta.clone()).collect(),
            text_metadata: text.iter().map(|(m, _)| m.clone()).collect(),
            ..Default::default()
        })
    }))
    .await?;
    ctl.update(Update::WaitingForAccept);

    let resp = expect_frame(conn, &ctl.cancel, v1_frame::FrameType::Response).await?;
    match resp.connection_response.unwrap_or_default().status() {
        Status::Accept => {}
        Status::Reject => return Err(Stop::Rejected.into()),
        Status::NotEnoughSpace => bail!("the receiver doesn't have enough space"),
        Status::UnsupportedAttachmentType => bail!("the receiver doesn't support this content"),
        Status::TimedOut => bail!("the receiver didn't answer in time"),
        Status::Unknown => bail!("the receiver declined"),
    }
    ctl.update(Update::Transferring);

    let total = files.iter().map(|f| f.meta.size() as u64).sum::<u64>()
        + text.as_ref().map_or(0, |(_, t)| t.len() as u64);
    let mut progress = Progress::new(total);
    for f in &mut files {
        send_file(conn, &s, f, &mut progress, ctl).await?;
    }
    if let Some((meta, t)) = text {
        // Text goes as a BYTES payload with the announced payload ID.
        send_text(&s, meta.payload_id(), t.into_bytes()).await?;
        progress.add(meta.size() as u64, ctl);
    }
    Ok(())
}

async fn send_text(s: &PayloadSender, id: i64, data: Vec<u8>) -> anyhow::Result<()> {
    s.send_bytes_with_id(id, data).await
}

async fn send_file(
    conn: &mut Connection,
    s: &PayloadSender,
    f: &mut OutFile,
    progress: &mut Progress,
    ctl: &Control,
) -> anyhow::Result<()> {
    let (id, size, name) = (f.meta.payload_id(), f.meta.size(), f.meta.name().to_owned());
    let mut offset = 0i64;
    while offset < size {
        // The chunk size grows if the connection is upgraded while we send.
        // Each chunk is read straight into the buffer that gets sent.
        let want = s.chunk_size().min((size - offset) as usize);
        let mut chunk = Vec::with_capacity(want);
        (&mut f.file).take(want as u64).read_to_end(&mut chunk).await?;
        let n = chunk.len();
        if n == 0 {
            bail!("{name} shrank while sending");
        }
        let send = s.send_file_chunk(id, &name, size, offset, chunk, false);
        tokio::select! {
            r = send => r?,
            _ = ctl.cancel.cancelled() => {
                let _ = s.cancel_payload(id, PayloadType::File, offset).await;
                return Err(Stop::LocalCancel.into());
            }
            ev = conn.recv() => return Err(match ev? {
                Event::Bytes { data, .. } if is_cancel(&data) => Stop::PeerCancel.into(),
                Event::PayloadCanceled(_) => Stop::PeerCancel.into(),
                Event::Disconnected => anyhow::anyhow!("the other device disconnected"),
                ev => anyhow::anyhow!("unexpected {ev:?} while sending"),
            }),
        }
        offset += n as i64;
        progress.add(n as u64, ctl);
    }
    s.send_file_chunk(id, &name, size, size, Vec::new(), true).await
}

fn is_cancel(data: &[u8]) -> bool {
    Frame::decode(data)
        .ok()
        .and_then(|f| f.v1)
        .is_some_and(|v| v.r#type() == v1_frame::FrameType::Cancel)
}

// -------------------------------------------------------------- receiving

pub struct Incoming {
    pub decision: oneshot::Receiver<bool>,
    pub download_dir: PathBuf,
}

/// A file being received.
struct InFile {
    payload_id: i64,
    size: u64,
    written: u64,
    name: String,
    /// Set once the file has been created.
    path: Option<PathBuf>,
    file: Option<tokio::io::BufWriter<tokio::fs::File>>,
}

/// A file name from the peer reduced to a single safe path component.
pub fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = base.chars().filter(|c| !c.is_control()).collect();
    s = s.trim().to_owned();
    if s.is_empty() || s == "." || s == ".." {
        s = "file".into();
    }
    if s.starts_with('.') {
        s.replace_range(..1, "_");
    }
    while s.len() > 200 {
        s.pop();
    }
    s
}

/// Creates `dir/name`, or `name (1)`, `name (2)`... if it exists.
async fn create_unique(dir: &Path, name: &str) -> anyhow::Result<(PathBuf, tokio::fs::File)> {
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = p.extension().and_then(|e| e.to_str());
    for i in 0..1000 {
        let candidate = match (i, ext) {
            (0, _) => name.to_owned(),
            (_, Some(ext)) => format!("{stem} ({i}).{ext}"),
            (_, None) => format!("{stem} ({i})"),
        };
        let path = dir.join(candidate);
        match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&path).await {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
        }
    }
    bail!("too many files named {name}")
}

fn free_space(dir: &Path) -> Option<u64> {
    let st = nix::sys::statvfs::statvfs(dir).ok()?;
    Some(st.blocks_available() as u64 * st.fragment_size() as u64)
}

pub async fn receive(mut conn: Connection, remote: Remote, inc: Incoming, ctl: Control) {
    let mut files = Vec::new();
    let r = run_receive(&mut conn, remote, inc, &mut files, &ctl).await;
    match &r {
        Ok(_) => conn.close().await,
        Err(e) => {
            match e.downcast_ref::<Stop>() {
                Some(Stop::LocalCancel) => abort(conn, &ctl.lingers).await,
                Some(Stop::Rejected | Stop::Refused(_)) => {
                    ctl.lingers.spawn(close_after(conn, REJECT_LINGER));
                }
                _ => conn.close().await,
            }
            for f in &files {
                if let Some(path) = &f.path
                    && (f.file.is_some() || f.written < f.size) {
                        let _ = tokio::fs::remove_file(path).await;
                    }
            }
        }
    }
    ctl.update(final_update(r));
}

async fn run_receive(
    conn: &mut Connection,
    remote: Remote,
    mut inc: Incoming,
    files: &mut Vec<InFile>,
    ctl: &Control,
) -> anyhow::Result<Update> {
    let (peer_type, peer_name) = decode_endpoint_info(&remote.endpoint_info)?;
    let peer_name = peer_name.unwrap_or_else(|| "Unknown device".into());
    let s = conn.sender();

    exchange_paired_keys(conn, &ctl.cancel).await?;
    // Samsung's early RESPONSE (ACCEPT) frame, the one ignored while waiting
    // for the user's decision below, sometimes arrives before the
    // Introduction instead of after it.
    let intro = loop {
        let f = next_frame(conn, &ctl.cancel).await?;
        match f.r#type() {
            v1_frame::FrameType::Introduction => break f,
            v1_frame::FrameType::Response => tracing::debug!("ignoring sharing response before the introduction"),
            t => bail!("expected Introduction, got {t:?}"),
        }
    };
    let intro = intro.introduction.unwrap_or_default();

    // Check the offer as Chrome does (OnReceivedIntroduction): every text
    // must have a positive size, every network a name, and there must be
    // something to receive. Chrome also refuses empty files; we accept them
    // (nearcast sends them) and only refuse negative sizes.
    let bad_file = intro.file_metadata.iter().any(|m| m.size() < 0);
    let bad_text = intro.text_metadata.iter().any(|m| m.size() <= 0);
    let bad_wifi = intro.wifi_credentials_metadata.iter().any(|m| m.ssid().is_empty());
    let offered =
        intro.file_metadata.len() + intro.text_metadata.len() + intro.wifi_credentials_metadata.len();
    if offered == 0 || bad_file || bad_text || bad_wifi {
        send_response(&s, Status::UnsupportedAttachmentType).await?;
        return Err(Stop::Refused("unsupported content offered".into()).into());
    }
    let mut entries = Vec::new();
    for m in &intro.file_metadata {
        let name = safe_file_name(m.name());
        entries.push(FileEntry { name: name.clone(), size: m.size() as u64 });
        files.push(InFile { payload_id: m.payload_id(), size: m.size() as u64, written: 0, name, path: None, file: None });
    }
    let texts: Vec<(i64, OfferedText)> = intro
        .text_metadata
        .iter()
        .map(|m| {
            let kind = match m.r#type() {
                text_metadata::Type::Url => TextKind::Url,
                text_metadata::Type::Address => TextKind::Address,
                text_metadata::Type::PhoneNumber => TextKind::PhoneNumber,
                _ => TextKind::Text,
            };
            (m.payload_id(), OfferedText { kind, title: m.text_title().to_owned() })
        })
        .collect();
    let wifi: Vec<(i64, OfferedWifi)> = intro
        .wifi_credentials_metadata
        .iter()
        .map(|m| {
            let security = match m.security_type() {
                wifi_credentials_metadata::SecurityType::Open => WifiSecurity::Open,
                wifi_credentials_metadata::SecurityType::WpaPsk => WifiSecurity::WpaPsk,
                wifi_credentials_metadata::SecurityType::Wep => WifiSecurity::Wep,
                _ => WifiSecurity::Unknown,
            };
            (m.payload_id(), OfferedWifi { ssid: m.ssid().to_owned(), security })
        })
        .collect();

    ctl.update(Update::Incoming {
        peer_name,
        peer_type,
        pin: conn.pin().to_owned(),
        files: entries,
        texts: texts.iter().map(|(_, t)| t.clone()).collect(),
        wifi: wifi.iter().map(|(_, w)| w.clone()).collect(),
    });

    // Keep-alives are answered by the connection while we wait. Other
    // sharing frames (some senders send their own Response here) don't
    // change anything until the user decides.
    let accepted = loop {
        tokio::select! {
            d = &mut inc.decision => break d.unwrap_or(false),
            _ = ctl.cancel.cancelled() => break false,
            ev = conn.recv() => match ev? {
                Event::Bytes { data, .. } if is_cancel(&data) => return Err(Stop::PeerCancel.into()),
                // Samsung senders send a sharing RESPONSE (ACCEPT) frame
                // here, before we answer; it carries nothing we need.
                Event::Bytes { .. } => tracing::debug!("ignoring sharing frame while waiting for a decision"),
                Event::PayloadCanceled(_) | Event::Disconnected => return Err(Stop::PeerCancel.into()),
                ev => bail!("unexpected {ev:?} before accepting"),
            },
        }
    };
    if !accepted {
        send_response(&s, Status::Reject).await?;
        return Err(Stop::Rejected.into());
    }

    let total: u64 = files.iter().map(|f| f.size).sum();
    if free_space(&inc.download_dir).is_some_and(|free| free < total) {
        send_response(&s, Status::NotEnoughSpace).await?;
        return Err(Stop::Refused(format!("not enough space in {}", inc.download_dir.display())).into());
    }
    tokio::fs::create_dir_all(&inc.download_dir).await?;
    for f in files.iter_mut() {
        let (path, file) = create_unique(&inc.download_dir, &f.name).await?;
        f.path = Some(path);
        f.file = Some(tokio::io::BufWriter::with_capacity(RECEIVE_BUFFER, file));
    }
    send_response(&s, Status::Accept).await?;
    ctl.update(Update::Transferring);

    let mut progress = Progress::new(total);
    let mut text_payloads: HashMap<i64, String> = HashMap::new();
    let mut wifi_payloads: HashMap<i64, ReceivedWifi> = HashMap::new();
    let mut remaining = files.len() + texts.len() + wifi.len();
    while remaining > 0 {
        let ev = tokio::select! {
            _ = ctl.cancel.cancelled() => return Err(Stop::LocalCancel.into()),
            ev = conn.recv() => ev?,
        };
        match ev {
            Event::FileChunk { id, offset, total: announced, data, last } => {
                let f = files.iter_mut().find(|f| f.payload_id == id).context("data for an unknown file")?;
                let file = f.file.as_mut().context("data after the end of a file")?;
                if announced as u64 != f.size || offset as u64 != f.written {
                    bail!("file data out of order");
                }
                if f.written + data.len() as u64 > f.size {
                    bail!("file larger than announced");
                }
                file.write_all(&data).await?;
                f.written += data.len() as u64;
                progress.add(data.len() as u64, ctl);
                if last {
                    if f.written != f.size {
                        bail!("file ended early");
                    }
                    file.flush().await?;
                    f.file = None;
                    remaining -= 1;
                }
            }
            Event::Bytes { id, data } if texts.iter().any(|(t, _)| *t == id) => {
                if text_payloads.insert(id, String::from_utf8_lossy(&data).into_owned()).is_none() {
                    remaining -= 1;
                }
            }
            Event::Bytes { id, data } if wifi.iter().any(|(w, _)| *w == id) => {
                let creds = WifiCredentials::decode(&*data).context("bad Wi-Fi credentials")?;
                let received = ReceivedWifi { password: creds.password().to_owned(), hidden: creds.hidden_ssid() };
                if wifi_payloads.insert(id, received).is_none() {
                    remaining -= 1;
                }
            }
            Event::Bytes { data, .. } if is_cancel(&data) => return Err(Stop::PeerCancel.into()),
            Event::Bytes { .. } => {}
            Event::PayloadCanceled(_) => return Err(Stop::PeerCancel.into()),
            Event::Disconnected => bail!("the other device disconnected"),
        }
    }
    Ok(Update::Finished {
        saved: files.iter().filter_map(|f| f.path.clone()).collect(),
        texts: texts.iter().filter_map(|(id, _)| text_payloads.remove(id)).collect(),
        wifi: wifi.iter().filter_map(|(id, _)| wifi_payloads.remove(id)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{self, Local};
    use crate::endpoint::encode_endpoint_info;
    use crate::proto::sharing::WifiCredentialsMetadata;
    use tokio::net::TcpListener;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("..\\x.txt"), "x.txt");
        assert_eq!(safe_file_name(".bashrc"), "_bashrc");
        assert_eq!(safe_file_name(".."), "file");
        assert_eq!(safe_file_name("a\nb.jpg"), "ab.jpg");
        assert_eq!(safe_file_name("photo.jpg"), "photo.jpg");
    }

    #[test]
    fn urls_are_detected() {
        assert_eq!(text_kind("https://example.com/x"), TextKind::Url);
        assert_eq!(text_kind("see https://example.com"), TextKind::Text);
    }

    async fn run_pair(
        files: Vec<PathBuf>,
        text: Option<String>,
        accept: bool,
        dir: PathBuf,
    ) -> (Vec<Update>, Vec<Update>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (rx_tx, mut rx_updates) = mpsc::unbounded_channel();
        let (dec_tx, dec_rx) = oneshot::channel();
        let receiver = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (conn, remote) = connection::accept(sock, &Local { endpoint_id: *b"RECV", endpoint_info: vec![], upgrades: None }).await.unwrap();
            let ctl = Control { cancel: CancellationToken::new(), updates: rx_tx, lingers: TaskTracker::new() };
            receive(conn, remote, Incoming { decision: dec_rx, download_dir: dir }, ctl).await;
        });
        let local = Local { endpoint_id: *b"ABCD", endpoint_info: encode_endpoint_info(DeviceType::Laptop, "tester"), upgrades: None };
        let (tx_tx, mut tx_updates) = mpsc::unbounded_channel();
        let sender = tokio::spawn(async move {
            let ctl = Control { cancel: CancellationToken::new(), updates: tx_tx, lingers: TaskTracker::new() };
            let connect = Box::pin(async move { connection::connect(addr, &local).await });
            send(Outgoing { connect, files, text }, ctl).await;
        });
        let mut rx_log = Vec::new();
        let mut dec_tx = Some(dec_tx);
        while let Some(u) = rx_updates.recv().await {
            if let Update::Incoming { .. } = u {
                dec_tx.take().unwrap().send(accept).unwrap();
            }
            rx_log.push(u);
        }
        receiver.await.unwrap();
        sender.await.unwrap();
        let mut tx_log = Vec::new();
        while let Ok(u) = tx_updates.try_recv() {
            tx_log.push(u);
        }
        (tx_log, rx_log)
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nearcast-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn sends_files_end_to_end() {
        let src = scratch("src");
        let dst = scratch("dst");
        let big: Vec<u8> = (0..(connection::CHUNK_SIZE * 2 + 123)).map(|i| (i % 251) as u8).collect();
        std::fs::write(src.join("big.bin"), &big).unwrap();
        std::fs::write(src.join("empty.txt"), b"").unwrap();
        std::fs::write(dst.join("big.bin"), b"existing").unwrap();

        let (tx, rx) = run_pair(vec![src.join("big.bin"), src.join("empty.txt")], None, true, dst.clone()).await;
        assert!(matches!(tx.last(), Some(Update::Finished { .. })), "{tx:?}");
        let Some(Update::Finished { saved, .. }) = rx.last() else { panic!("{rx:?}") };
        assert_eq!(saved.len(), 2);
        assert_eq!(std::fs::read(dst.join("big (1).bin")).unwrap(), big);
        assert_eq!(std::fs::read(dst.join("big.bin")).unwrap(), b"existing");
        assert_eq!(std::fs::read(dst.join("empty.txt")).unwrap(), b"");
    }

    #[tokio::test]
    async fn sends_text_and_handles_rejection() {
        let dst = scratch("text");
        let (_, rx) = run_pair(vec![], Some("https://example.com".into()), true, dst.clone()).await;
        let Some(Update::Finished { texts, .. }) = rx.last() else { panic!("{rx:?}") };
        assert_eq!(texts, &["https://example.com".to_string()]);

        let (tx, rx) = run_pair(vec![], Some("hi".into()), false, dst).await;
        assert!(matches!(tx.last(), Some(Update::Rejected)), "{tx:?}");
        assert!(matches!(rx.last(), Some(Update::Rejected)), "{rx:?}");
    }

    /// A sender that, like Samsung's, sends RESPONSE (ACCEPT) before its
    /// Introduction still gets its share offered to the user.
    #[tokio::test]
    async fn early_response_before_introduction_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (rx_tx, mut rx_updates) = mpsc::unbounded_channel();
        let (dec_tx, dec_rx) = oneshot::channel();
        let dir = scratch("early");
        let receiver = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (conn, remote) = connection::accept(sock, &Local { endpoint_id: *b"RECV", endpoint_info: vec![], upgrades: None }).await.unwrap();
            let ctl = Control { cancel: CancellationToken::new(), updates: rx_tx, lingers: TaskTracker::new() };
            receive(conn, remote, Incoming { decision: dec_rx, download_dir: dir }, ctl).await;
        });
        let local = Local { endpoint_id: *b"ABCD", endpoint_info: encode_endpoint_info(DeviceType::Phone, "samsung"), upgrades: None };
        let mut conn = connection::connect(addr, &local).await.unwrap();
        let cancel = CancellationToken::new();
        exchange_paired_keys(&mut conn, &cancel).await.unwrap();
        let s = conn.sender();
        send_response(&s, Status::Accept).await.unwrap();
        s.send_bytes(sharing_frame(v1_frame::FrameType::Introduction, |f| {
            f.introduction = Some(IntroductionFrame {
                text_metadata: vec![TextMetadata {
                    text_title: Some("hi".into()),
                    payload_id: Some(1),
                    size: Some(2),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }))
        .await
        .unwrap();

        let mut rx_log = Vec::new();
        let mut dec_tx = Some(dec_tx);
        while let Some(u) = rx_updates.recv().await {
            if let Update::Incoming { .. } = u {
                dec_tx.take().unwrap().send(false).unwrap();
            }
            rx_log.push(u);
        }
        receiver.await.unwrap();
        assert!(rx_log.iter().any(|u| matches!(u, Update::Incoming { .. })), "{rx_log:?}");
        assert!(matches!(rx_log.last(), Some(Update::Rejected)), "{rx_log:?}");
    }
    /// After rejecting, the receiver reports it at once but keeps the
    /// connection open for REJECT_LINGER, so a phone can process the REJECT
    /// before it sees the disconnection (it otherwise reports a failure).
    #[tokio::test]
    async fn rejection_reaches_the_peer_before_the_connection_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (rx_tx, mut rx_updates) = mpsc::unbounded_channel();
        let (dec_tx, dec_rx) = oneshot::channel();
        let dir = scratch("linger");
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (conn, remote) = connection::accept(sock, &Local { endpoint_id: *b"RECV", endpoint_info: vec![], upgrades: None }).await.unwrap();
            let ctl = Control { cancel: CancellationToken::new(), updates: rx_tx, lingers: TaskTracker::new() };
            receive(conn, remote, Incoming { decision: dec_rx, download_dir: dir }, ctl).await;
        });
        let local = Local { endpoint_id: *b"ABCD", endpoint_info: encode_endpoint_info(DeviceType::Phone, "phone"), upgrades: None };
        let mut conn = connection::connect(addr, &local).await.unwrap();
        let cancel = CancellationToken::new();
        exchange_paired_keys(&mut conn, &cancel).await.unwrap();
        conn.sender()
            .send_bytes(sharing_frame(v1_frame::FrameType::Introduction, |f| {
                f.introduction = Some(IntroductionFrame {
                    text_metadata: vec![TextMetadata { text_title: Some("hi".into()), payload_id: Some(1), size: Some(2), ..Default::default() }],
                    ..Default::default()
                })
            }))
            .await
            .unwrap();

        let mut dec_tx = Some(dec_tx);
        let started = loop {
            match rx_updates.recv().await.unwrap() {
                Update::Incoming { .. } => dec_tx.take().unwrap().send(false).unwrap(),
                Update::Rejected => break Instant::now(),
                _ => {}
            }
        };

        // The REJECT arrives...
        let resp = match conn.recv().await.unwrap() {
            Event::Bytes { data, .. } => Frame::decode(&*data).unwrap(),
            ev => panic!("expected the response, got {ev:?}"),
        };
        let status = resp.v1.unwrap().connection_response.unwrap().status();
        assert_eq!(status, Status::Reject);
        // ...and the connection stays up for the linger time, then closes.
        let closed = loop {
            match conn.recv().await {
                Ok(Event::Disconnected) | Err(_) => break started.elapsed(),
                Ok(_) => {}
            }
        };
        assert!(closed >= REJECT_LINGER - Duration::from_millis(200), "closed after {closed:?}");
        assert!(closed < REJECT_LINGER + Duration::from_secs(2), "closed after {closed:?}");
    }
    /// Two texts and a Wi-Fi network in one share all arrive, in the order
    /// offered, as Chrome accepts them; a file with a negative size is refused.
    #[tokio::test]
    async fn receives_several_texts_and_wifi_credentials() {
        async fn offer(intro: IntroductionFrame, payloads: Vec<(i64, Vec<u8>)>) -> Vec<Update> {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (rx_tx, mut rx_updates) = mpsc::unbounded_channel();
            let (dec_tx, dec_rx) = oneshot::channel();
            let dir = scratch("multi");
            tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                let (conn, remote) = connection::accept(sock, &Local { endpoint_id: *b"RECV", endpoint_info: vec![], upgrades: None }).await.unwrap();
                let ctl = Control { cancel: CancellationToken::new(), updates: rx_tx, lingers: TaskTracker::new() };
                receive(conn, remote, Incoming { decision: dec_rx, download_dir: dir }, ctl).await;
            });
            let local = Local { endpoint_id: *b"ABCD", endpoint_info: encode_endpoint_info(DeviceType::Phone, "phone"), upgrades: None };
            let mut conn = connection::connect(addr, &local).await.unwrap();
            exchange_paired_keys(&mut conn, &CancellationToken::new()).await.unwrap();
            let s = conn.sender();
            s.send_bytes(sharing_frame(v1_frame::FrameType::Introduction, |f| f.introduction = Some(intro)))
                .await
                .unwrap();
            let mut log = Vec::new();
            let mut dec_tx = Some(dec_tx);
            while let Some(u) = rx_updates.recv().await {
                if let Update::Incoming { .. } = u {
                    dec_tx.take().unwrap().send(true).unwrap();
                    // Wait for ACCEPT, then send the payloads.
                    loop {
                        if let Event::Bytes { .. } = conn.recv().await.unwrap() {
                            break;
                        }
                    }
                    for (id, data) in &payloads {
                        s.send_bytes_with_id(*id, data.clone()).await.unwrap();
                    }
                }
                log.push(u);
            }
            log
        }

        let text = |id: i64, title: &str| TextMetadata {
            text_title: Some(title.into()),
            payload_id: Some(id),
            size: Some(title.len() as i64),
            ..Default::default()
        };
        let intro = IntroductionFrame {
            text_metadata: vec![text(1, "first"), text(2, "https://example.com")],
            wifi_credentials_metadata: vec![WifiCredentialsMetadata {
                ssid: Some("home".into()),
                security_type: Some(wifi_credentials_metadata::SecurityType::WpaPsk.into()),
                payload_id: Some(3),
                ..Default::default()
            }],
            ..Default::default()
        };
        let creds = WifiCredentials { password: Some("hunter22".into()), hidden_ssid: Some(true) };
        // Payloads arrive in a different order than offered.
        let log = offer(
            intro,
            vec![(3, creds.encode_to_vec()), (2, b"https://example.com".to_vec()), (1, b"first".to_vec())],
        )
        .await;
        let Some(Update::Incoming { texts, wifi, .. }) = log.iter().find(|u| matches!(u, Update::Incoming { .. })) else {
            panic!("{log:?}")
        };
        assert_eq!(texts.len(), 2);
        assert_eq!(wifi, &[OfferedWifi { ssid: "home".into(), security: WifiSecurity::WpaPsk }]);
        let Some(Update::Finished { texts, wifi, .. }) = log.last() else { panic!("{log:?}") };
        assert_eq!(texts, &["first".to_string(), "https://example.com".to_string()]);
        assert_eq!(wifi, &[ReceivedWifi { password: "hunter22".into(), hidden: true }]);

        // A file with a negative size is refused before asking.
        let intro = IntroductionFrame {
            file_metadata: vec![FileMetadata { name: Some("bad".into()), size: Some(-1), payload_id: Some(9), ..Default::default() }],
            ..Default::default()
        };
        let log = offer(intro, vec![]).await;
        assert!(!log.iter().any(|u| matches!(u, Update::Incoming { .. })), "{log:?}");
        assert!(matches!(log.last(), Some(Update::Failed(_))), "{log:?}");
    }
}
