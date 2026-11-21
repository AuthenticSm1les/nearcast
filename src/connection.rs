//! Nearby Connections over an established byte stream: connection request and
//! response, UKEY2, then encrypted offline frames carrying payloads,
//! keep-alives and disconnection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use prost::Message;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::proto::connections::bandwidth_upgrade_negotiation_frame::EventType as BwuEvent;
use crate::proto::connections::connection_request_frame::Medium;
use crate::proto::connections::connection_response_frame::ResponseStatus;
use crate::proto::connections::os_info::OsType;
use crate::proto::connections::payload_transfer_frame::control_message::EventType as ControlEvent;
use crate::proto::connections::payload_transfer_frame::payload_header::PayloadType;
use crate::proto::connections::payload_transfer_frame::{
    ControlMessage, PacketType, PayloadChunk, PayloadHeader,
};
use crate::proto::connections::{
    offline_frame, v1_frame, ConnectionRequestFrame,
    ConnectionResponseFrame, DisconnectionFrame, KeepAliveFrame, OfflineFrame, OsInfo,
    PayloadTransferFrame, V1Frame,
};
use crate::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium as BwuMedium;
use crate::ukey2;
use crate::upgrade::{self, BoxStream, BwuIn, Mediums, ReadSlot, StreamRead, StreamWrite, WriterCtl};
use crate::wire::{read_frame, write_frame, SecureReader, SecureWriter};

pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Size of the file chunks we send over Wi-Fi.
pub const CHUNK_SIZE: usize = 512 * 1024;
/// Smaller chunks over Bluetooth, so frames still flow every few seconds.
pub const BLUETOOTH_CHUNK_SIZE: usize = 64 * 1024;
/// Largest BYTES payload we buffer (these carry sharing frames and text).
const MAX_BYTES_PAYLOAD: i64 = 4 * 1024 * 1024;

/// Things that arrive on a connection.
#[derive(Debug)]
pub enum Event {
    /// A complete BYTES payload.
    Bytes { id: i64, data: Vec<u8> },
    /// A piece of a FILE payload; `last` is set on the final (possibly empty) chunk.
    FileChunk { id: i64, offset: i64, total: i64, data: Vec<u8>, last: bool },
    /// The peer cancelled (or failed) a payload.
    PayloadCanceled(i64),
    /// The peer disconnected cleanly.
    Disconnected,
}

/// Our side of the connection request.
pub struct Local {
    pub endpoint_id: [u8; 4],
    pub endpoint_info: Vec<u8>,
    /// Mediums we can upgrade to, if any.
    pub upgrades: Option<Arc<dyn Mediums>>,
}

/// What the peer told us in its connection request.
pub struct Remote {
    pub endpoint_id: String,
    pub endpoint_info: Vec<u8>,
    /// Mediums the peer can be upgraded to, in its order of preference.
    pub mediums: Vec<BwuMedium>,
}

/// Connection state the payload sender also needs.
struct Shared {
    /// The medium we are on now, as a [`BwuMedium`] number.
    medium: AtomicI32,
}

impl Shared {
    fn medium(&self) -> BwuMedium {
        BwuMedium::try_from(self.medium.load(Ordering::Relaxed)).unwrap_or(BwuMedium::UnknownMedium)
    }
}

pub struct Connection {
    out: mpsc::Sender<OfflineFrame>,
    events: mpsc::Receiver<anyhow::Result<Event>>,
    writer: Option<JoinHandle<anyhow::Result<()>>>,
    reader: JoinHandle<()>,
    /// Ends the upgrade task, which then lets go of any medium it set up.
    cancel: CancellationToken,
    pin: String,
    shared: Arc<Shared>,
}

/// Handle for sending payloads while another task reads events.
#[derive(Clone)]
pub struct PayloadSender {
    out: mpsc::Sender<OfflineFrame>,
    shared: Arc<Shared>,
}

fn v1(t: v1_frame::FrameType, f: impl FnOnce(&mut V1Frame)) -> OfflineFrame {
    let mut v1 = V1Frame { r#type: Some(t.into()), ..Default::default() };
    f(&mut v1);
    OfflineFrame { version: Some(offline_frame::Version::V1.into()), v1: Some(v1) }
}

fn keep_alive(ack: bool) -> OfflineFrame {
    v1(v1_frame::FrameType::KeepAlive, |f| f.keep_alive = Some(KeepAliveFrame { ack: Some(ack) }))
}

fn disconnection() -> OfflineFrame {
    v1(v1_frame::FrameType::Disconnection, |f| {
        f.disconnection = Some(DisconnectionFrame::default())
    })
}

#[allow(deprecated)] // Nearby still fills the old status field (0 = success).
fn connection_response(accept: bool) -> OfflineFrame {
    v1(v1_frame::FrameType::ConnectionResponse, |f| {
        f.connection_response = Some(ConnectionResponseFrame {
            status: Some(if accept { 0 } else { 1 }),
            response: Some(if accept { ResponseStatus::Accept } else { ResponseStatus::Reject }.into()),
            os_info: Some(OsInfo { r#type: Some(OsType::Linux.into()) }),
            ..Default::default()
        })
    })
}

fn frame_type(f: &OfflineFrame) -> v1_frame::FrameType {
    f.v1.as_ref().map(|v| v.r#type()).unwrap_or(v1_frame::FrameType::UnknownFrameType)
}

/// The link a connection starts on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Link {
    WifiLan,
    Bluetooth,
}

impl Link {
    fn medium(self) -> BwuMedium {
        match self {
            Link::WifiLan => BwuMedium::WifiLan,
            Link::Bluetooth => BwuMedium::Bluetooth,
        }
    }
}

/// File chunk size for a medium: smaller over Bluetooth, so frames still
/// flow every few seconds.
fn chunk_size(m: BwuMedium) -> usize {
    match m {
        BwuMedium::Bluetooth | BwuMedium::Ble => BLUETOOTH_CHUNK_SIZE,
        _ => CHUNK_SIZE,
    }
}

/// Connects to a peer on the local network.
pub async fn connect(addr: SocketAddr, local: &Local) -> anyhow::Result<Connection> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("timed out connecting")??;
    stream.set_nodelay(true)?;
    connect_stream(stream, Link::WifiLan, local).await
}

/// Runs the client side of the handshake on an open stream.
pub async fn connect_stream<S>(stream: S, link: Link, local: &Local) -> anyhow::Result<Connection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let mut stream: BoxStream = Box::new(stream);
        // The mediums we could be upgraded to, and the one we are on.
        let mut mediums: Vec<i32> =
            local.upgrades.iter().flat_map(|u| u.joinable()).map(i32::from).collect();
        let current = i32::from(link.medium());
        if !mediums.contains(&current) {
            mediums.push(current);
        }
        let request = v1(v1_frame::FrameType::ConnectionRequest, |f| {
            f.connection_request = Some(ConnectionRequestFrame {
                endpoint_id: Some(String::from_utf8_lossy(&local.endpoint_id).into_owned()),
                endpoint_name: Some(local.endpoint_info.clone()),
                endpoint_info: Some(local.endpoint_info.clone()),
                nonce: Some(rand::rng().random()),
                // Both enums number mediums the same way.
                mediums: mediums.into_iter().filter(|m| Medium::try_from(*m).is_ok()).collect(),
                keep_alive_interval_millis: Some(KEEP_ALIVE_INTERVAL.as_millis() as i32),
                keep_alive_timeout_millis: Some(KEEP_ALIVE_TIMEOUT.as_millis() as i32),
                ..Default::default()
            })
        });
        write_frame(&mut stream, &request.encode_to_vec()).await?;
        let keys = ukey2::client(&mut stream).await?;
        finish(stream, keys, link, local, None).await
    })
    .await
    .context("handshake timed out")?
}

/// Runs the server side of the handshake on an accepted TCP socket.
pub async fn accept(stream: TcpStream, local: &Local) -> anyhow::Result<(Connection, Remote)> {
    stream.set_nodelay(true)?;
    accept_stream(stream, Link::WifiLan, local).await
}

/// Runs the server side of the handshake on an accepted stream.
pub async fn accept_stream<S>(stream: S, link: Link, local: &Local) -> anyhow::Result<(Connection, Remote)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let mut stream: BoxStream = Box::new(stream);
        let frame = OfflineFrame::decode(&*read_frame(&mut stream).await?)?;
        if frame_type(&frame) != v1_frame::FrameType::ConnectionRequest {
            bail!("expected a connection request, got {:?}", frame_type(&frame));
        }
        let req = frame.v1.and_then(|v| v.connection_request).context("empty connection request")?;
        let remote = Remote {
            endpoint_id: req.endpoint_id().to_owned(),
            endpoint_info: req.endpoint_info().to_vec(),
            mediums: req.mediums.iter().filter_map(|m| upgrade::medium_from_i32(*m)).collect(),
        };
        tracing::debug!("peer {} can upgrade to {:?}", remote.endpoint_id, remote.mediums);
        let keys = ukey2::server(&mut stream).await?;
        let host_for = Some((remote.endpoint_id.clone(), remote.mediums.clone()));
        Ok((finish(stream, keys, link, local, host_for).await?, remote))
    })
    .await
    .context("handshake timed out")?
}

/// Exchanges connection responses (in the clear) and starts the encrypted
/// channel. `host_for` is set when we accepted the connection, which makes us
/// the side that starts a bandwidth upgrade.
async fn finish(
    mut stream: BoxStream,
    keys: ukey2::Keys,
    link: Link,
    local: &Local,
    host_for: Option<(String, Vec<BwuMedium>)>,
) -> anyhow::Result<Connection> {
    write_frame(&mut stream, &connection_response(true).encode_to_vec()).await?;
    let frame = OfflineFrame::decode(&*read_frame(&mut stream).await?)?;
    if frame_type(&frame) != v1_frame::FrameType::ConnectionResponse {
        bail!("expected a connection response, got {:?}", frame_type(&frame));
    }
    let resp = frame.v1.and_then(|v| v.connection_response).unwrap_or_default();
    if resp.response() != ResponseStatus::Accept {
        bail!("the peer rejected the connection");
    }

    let pin = keys.pin();
    let (r, w) = tokio::io::split(stream);
    let (out, out_rx) = mpsc::channel(4);
    let (ctl, ctl_rx) = mpsc::unbounded_channel();
    let (ev_tx, events) = mpsc::channel(16);
    let shared = Arc::new(Shared { medium: AtomicI32::new(link.medium().into()) });
    let slot: ReadSlot = Arc::new(Mutex::new(None));
    let cancel = CancellationToken::new();

    let bwu_tx = local.upgrades.clone().map(|mediums| {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = upgrade::Task {
            mediums,
            endpoint_id: String::from_utf8_lossy(&local.endpoint_id).into_owned(),
            // Upgrading only pays off over Bluetooth.
            host_for: host_for.filter(|_| link == Link::Bluetooth),
            current: link.medium(),
            ctl: ctl.clone(),
            slot: slot.clone(),
            rx,
            cancel: cancel.clone(),
        };
        tokio::spawn(task.run());
        tx
    });
    let writer = tokio::spawn({
        let task = writer_task(SecureWriter::new(w, keys.send), out_rx, ctl_rx, ctl.clone(), shared.clone());
        async move {
            let r = task.await;
            if let Err(e) = &r {
                tracing::debug!("connection writer stopped: {e:#}");
            }
            r
        }
    });
    let reader = tokio::spawn(reader_task(SecureReader::new(r, keys.recv), ctl, slot, bwu_tx, ev_tx));
    Ok(Connection { out, events, writer: Some(writer), reader, cancel, pin, shared })
}

async fn writer_task(
    mut w: SecureWriter<StreamWrite>,
    mut rx: mpsc::Receiver<OfflineFrame>,
    mut ctl: mpsc::UnboundedReceiver<WriterCtl>,
    // Keeps `ctl` open for as long as this task runs.
    _ctl_tx: mpsc::UnboundedSender<WriterCtl>,
    shared: Arc<Shared>,
) -> anyhow::Result<()> {
    let start = tokio::time::Instant::now() + KEEP_ALIVE_INTERVAL;
    let mut tick = tokio::time::interval_at(start, KEEP_ALIVE_INTERVAL);
    // The new channel during a bandwidth upgrade. Payloads and keep-alives
    // wait until we have moved to it, since they share the old channel's
    // sequence numbers.
    let mut next: Option<(StreamWrite, BwuMedium)> = None;
    // The peer's LAST_WRITE can arrive before we have joined the new channel
    // ourselves. SAFE_TO_CLOSE then waits for our own LAST_WRITE, as in
    // Nearby, because the peer closes the old channel once it has it.
    let mut peer_done = false;
    let safe_to_close = || upgrade::bwu_frame(BwuEvent::SafeToClosePriorChannel, |_| {});
    loop {
        tokio::select! {
            biased;
            c = ctl.recv() => match c.expect("writer holds a sender") {
                WriterCtl::Frame(f) => w.send(&f).await?,
                WriterCtl::KeepAliveAck => {
                    if next.is_none() {
                        w.send(&keep_alive(true)).await?;
                    }
                }
                WriterCtl::Begin(new, medium) => {
                    w.send(&upgrade::bwu_frame(BwuEvent::LastWriteToPriorChannel, |_| {})).await?;
                    next = Some((new, medium));
                    if std::mem::take(&mut peer_done) {
                        w.send(&safe_to_close()).await?;
                    }
                }
                WriterCtl::SafeToClose => {
                    if next.is_some() {
                        w.send(&safe_to_close()).await?;
                    } else {
                        peer_done = true;
                    }
                }
                WriterCtl::Switch => {
                    let (new, medium) = next.take().context("peer closed the prior channel before we upgraded")?;
                    // Nearby ends the prior channel with an unencrypted
                    // disconnection, outside the sequence numbering.
                    let _ = w.send_plain(&disconnection()).await;
                    let mut old = w.replace(new);
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut old).await;
                    shared.medium.store(medium.into(), Ordering::Relaxed);
                    tracing::info!("connection upgraded to {medium:?}");
                }
            },
            f = rx.recv(), if next.is_none() => match f {
                Some(f) => {
                    w.send(&f).await?;
                    if frame_type(&f) == v1_frame::FrameType::Disconnection {
                        break;
                    }
                }
                None => break,
            },
            _ = tick.tick(), if next.is_none() => w.send(&keep_alive(false)).await?,
        }
    }
    w.shutdown().await;
    Ok(())
}

async fn reader_task(
    mut r: SecureReader<StreamRead>,
    ctl: mpsc::UnboundedSender<WriterCtl>,
    slot: ReadSlot,
    bwu: Option<mpsc::UnboundedSender<BwuIn>>,
    events: mpsc::Sender<anyhow::Result<Event>>,
) {
    let mut bytes: HashMap<i64, Vec<u8>> = HashMap::new();
    loop {
        let frame = match tokio::time::timeout(KEEP_ALIVE_TIMEOUT, r.recv()).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                let eof = e
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof);
                let _ = events
                    .send(Err(if eof { anyhow::anyhow!("connection closed by peer") } else { e }))
                    .await;
                return;
            }
            Err(_) => {
                let _ = events.send(Err(anyhow::anyhow!("peer stopped responding"))).await;
                return;
            }
        };
        let Some(v1) = frame.v1 else { continue };
        let ev = match v1.r#type() {
            v1_frame::FrameType::KeepAlive => {
                if !v1.keep_alive.unwrap_or_default().ack() {
                    let _ = ctl.send(WriterCtl::KeepAliveAck);
                }
                continue;
            }
            v1_frame::FrameType::Disconnection => {
                let _ = events.send(Ok(Event::Disconnected)).await;
                return;
            }
            v1_frame::FrameType::PayloadTransfer => {
                match payload_event(v1.payload_transfer.unwrap_or_default(), &mut bytes) {
                    Ok(Some(ev)) => Ok(ev),
                    Ok(None) => continue,
                    Err(e) => Err(e),
                }
            }
            v1_frame::FrameType::BandwidthUpgradeNegotiation => {
                let b = v1.bandwidth_upgrade_negotiation.unwrap_or_default();
                match b.event_type() {
                    BwuEvent::UpgradePathAvailable => {
                        let info = b.upgrade_path_info.unwrap_or_default();
                        match &bwu {
                            Some(tx) => {
                                let _ = tx.send(BwuIn::PathAvailable(Box::new(info)));
                            }
                            // No mediums to upgrade to: decline.
                            None => {
                                let _ = ctl.send(WriterCtl::Frame(Box::new(upgrade::bwu_frame(
                                    BwuEvent::UpgradeFailure,
                                    |f| f.upgrade_path_info = Some(info),
                                ))));
                            }
                        }
                    }
                    BwuEvent::UpgradeFailure => {
                        if let Some(tx) = &bwu {
                            let _ = tx.send(BwuIn::Failure);
                        }
                    }
                    BwuEvent::LastWriteToPriorChannel => {
                        let _ = ctl.send(WriterCtl::SafeToClose);
                    }
                    BwuEvent::SafeToClosePriorChannel => {
                        // Everything after this comes on the new channel.
                        let Some(new) = slot.lock().unwrap().take() else {
                            let _ = events.send(Err(anyhow::anyhow!("peer switched channels without an upgrade"))).await;
                            return;
                        };
                        drop(r.replace(new));
                        let _ = ctl.send(WriterCtl::Switch);
                    }
                    e => tracing::debug!("ignoring bandwidth upgrade event {e:?}"),
                }
                continue;
            }
            t => {
                tracing::debug!("ignoring {t:?} frame");
                continue;
            }
        };
        let fatal = ev.is_err();
        if events.send(ev).await.is_err() || fatal {
            return;
        }
    }
}

fn payload_event(
    p: PayloadTransferFrame,
    bytes: &mut HashMap<i64, Vec<u8>>,
) -> anyhow::Result<Option<Event>> {
    let control = p.packet_type() == PacketType::Control;
    let header = p.payload_header.unwrap_or_default();
    let id = header.id();
    if control {
        let ctl = p.control_message.unwrap_or_default();
        return Ok(match ctl.event() {
            ControlEvent::PayloadCanceled | ControlEvent::PayloadError => {
                bytes.remove(&id);
                Some(Event::PayloadCanceled(id))
            }
            _ => None,
        });
    }
    let chunk = p.payload_chunk.unwrap_or_default();
    let last = chunk.flags() & 1 != 0;
    match header.r#type() {
        PayloadType::Bytes => {
            if header.total_size() > MAX_BYTES_PAYLOAD {
                bail!("bytes payload too large ({})", header.total_size());
            }
            let buf = bytes.entry(id).or_default();
            if chunk.offset() != buf.len() as i64 {
                bail!("bytes payload {id}: chunk at {} but have {}", chunk.offset(), buf.len());
            }
            buf.extend_from_slice(chunk.body());
            if buf.len() as i64 > header.total_size() {
                bail!("bytes payload {id} longer than announced");
            }
            if !last {
                return Ok(None);
            }
            Ok(bytes.remove(&id).map(|data| Event::Bytes { id, data }))
        }
        PayloadType::File => Ok(Some(Event::FileChunk {
            id,
            offset: chunk.offset(),
            total: header.total_size(),
            data: chunk.body.unwrap_or_default(),
            last,
        })),
        t => bail!("unsupported payload type {t:?}"),
    }
}

impl Connection {
    /// The 4-digit code derived from the handshake.
    pub fn pin(&self) -> &str {
        &self.pin
    }

    pub fn sender(&self) -> PayloadSender {
        PayloadSender { out: self.out.clone(), shared: self.shared.clone() }
    }

    /// The medium the connection is on now.
    pub fn medium(&self) -> BwuMedium {
        self.shared.medium()
    }

    /// Next event; an error means the connection is gone.
    pub async fn recv(&mut self) -> anyhow::Result<Event> {
        self.events.recv().await.unwrap_or_else(|| Err(anyhow::anyhow!("connection closed")))
    }

    /// Sends a disconnection frame and waits briefly for it to go out.
    pub async fn close(mut self) {
        let _ = self.out.send(disconnection()).await;
        if let Some(writer) = self.writer.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.reader.abort();
    }
}

impl PayloadSender {
    /// How big the file chunks on this connection should be now.
    pub fn chunk_size(&self) -> usize {
        chunk_size(self.shared.medium())
    }

    async fn send(&self, f: OfflineFrame) -> anyhow::Result<()> {
        self.out.send(f).await.map_err(|_| anyhow::anyhow!("connection closed"))
    }

    fn data(header: &PayloadHeader, offset: i64, last: bool, body: Vec<u8>) -> OfflineFrame {
        v1(v1_frame::FrameType::PayloadTransfer, |f| {
            f.payload_transfer = Some(PayloadTransferFrame {
                packet_type: Some(PacketType::Data.into()),
                payload_header: Some(header.clone()),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(if last { 1 } else { 0 }),
                    offset: Some(offset),
                    body: Some(body),
                }),
                ..Default::default()
            })
        })
    }

    /// Sends a whole BYTES payload.
    pub async fn send_bytes(&self, data: Vec<u8>) -> anyhow::Result<()> {
        let id = rand::rng().random();
        self.send_bytes_with_id(id, data).await
    }

    /// Sends a whole BYTES payload under a payload ID announced earlier.
    pub async fn send_bytes_with_id(&self, id: i64, data: Vec<u8>) -> anyhow::Result<()> {
        let header = PayloadHeader {
            id: Some(id),
            r#type: Some(PayloadType::Bytes.into()),
            total_size: Some(data.len() as i64),
            is_sensitive: Some(false),
            ..Default::default()
        };
        let len = data.len() as i64;
        self.send(Self::data(&header, 0, false, data)).await?;
        self.send(Self::data(&header, len, true, Vec::new())).await
    }

    /// Sends one chunk of a FILE payload. Call with an empty `body` and
    /// `last` set once the whole file has been sent.
    pub async fn send_file_chunk(
        &self,
        id: i64,
        name: &str,
        total: i64,
        offset: i64,
        body: Vec<u8>,
        last: bool,
    ) -> anyhow::Result<()> {
        let header = PayloadHeader {
            id: Some(id),
            r#type: Some(PayloadType::File.into()),
            total_size: Some(total),
            is_sensitive: Some(false),
            file_name: Some(name.to_owned()),
            ..Default::default()
        };
        self.send(Self::data(&header, offset, last, body)).await
    }

    /// Tells the peer we gave up on a payload.
    pub async fn cancel_payload(&self, id: i64, kind: PayloadType, offset: i64) -> anyhow::Result<()> {
        self.send(v1(v1_frame::FrameType::PayloadTransfer, |f| {
            f.payload_transfer = Some(PayloadTransferFrame {
                packet_type: Some(PacketType::Control.into()),
                payload_header: Some(PayloadHeader {
                    id: Some(id),
                    r#type: Some(kind.into()),
                    ..Default::default()
                }),
                control_message: Some(ControlMessage {
                    event: Some(ControlEvent::PayloadCanceled.into()),
                    offset: Some(offset),
                }),
                ..Default::default()
            })
        }))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_accept_and_exchange_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let local = Local { endpoint_id: *b"SERV", endpoint_info: vec![1; 4], upgrades: None };
            accept(s, &local).await.unwrap()
        });
        let local = Local { endpoint_id: *b"TEST", endpoint_info: vec![6; 20], upgrades: None };
        let client = connect(addr, &local).await.unwrap();
        let (mut server, remote) = server.await.unwrap();
        assert_eq!(remote.endpoint_id, "TEST");
        assert_eq!(remote.endpoint_info, vec![6; 20]);
        assert_eq!(client.pin(), server.pin());

        client.sender().send_bytes(b"hello".to_vec()).await.unwrap();
        match server.recv().await.unwrap() {
            Event::Bytes { data, .. } => assert_eq!(data, b"hello"),
            e => panic!("unexpected {e:?}"),
        }
        let s = client.sender();
        s.send_file_chunk(42, "f", 3, 0, b"abc".to_vec(), false).await.unwrap();
        s.send_file_chunk(42, "f", 3, 3, vec![], true).await.unwrap();
        assert!(matches!(server.recv().await.unwrap(), Event::FileChunk { id: 42, offset: 0, .. }));
        assert!(matches!(server.recv().await.unwrap(), Event::FileChunk { last: true, .. }));
        client.close().await;
        assert!(matches!(server.recv().await.unwrap(), Event::Disconnected));
    }

    /// Hosts and joins WIFI_LAN on the loopback address.
    struct Loopback {
        /// Fail joins, to exercise UPGRADE_FAILURE.
        refuse: bool,
    }

    impl Mediums for Loopback {
        fn hostable(&self) -> Vec<BwuMedium> {
            vec![BwuMedium::WifiLan]
        }
        fn joinable(&self) -> Vec<BwuMedium> {
            vec![BwuMedium::WifiLan]
        }
        fn host(&self, _: BwuMedium) -> futures_util::future::BoxFuture<'_, anyhow::Result<upgrade::Hosted>> {
            Box::pin(async {
                let l = TcpListener::bind("127.0.0.1:0").await?;
                let port = l.local_addr()?.port();
                Ok(upgrade::Hosted {
                    info: crate::proto::connections::bandwidth_upgrade_negotiation_frame::UpgradePathInfo {
                        wifi_lan_socket: Some(
                            crate::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::WifiLanSocket {
                                ip_address: Some(vec![127, 0, 0, 1]),
                                wifi_port: Some(port.into()),
                            },
                        ),
                        ..Default::default()
                    },
                    incoming: Box::pin(async move { Ok(Box::new(l.accept().await?.0) as BoxStream) }),
                    guard: Box::new(()),
                })
            })
        }
        fn join(
            &self,
            info: &crate::proto::connections::bandwidth_upgrade_negotiation_frame::UpgradePathInfo,
        ) -> futures_util::future::BoxFuture<'_, anyhow::Result<upgrade::Joined>> {
            let port = info.wifi_lan_socket.clone().unwrap_or_default().wifi_port() as u16;
            Box::pin(async move {
                if self.refuse {
                    bail!("refusing");
                }
                let s = TcpStream::connect(("127.0.0.1", port)).await?;
                Ok(upgrade::Joined { stream: Box::new(s), guard: Box::new(()) })
            })
        }
    }

    async fn pair_over_bluetooth(refuse: bool) -> (Connection, Connection) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let local = Local {
                endpoint_id: *b"SERV",
                endpoint_info: vec![1; 4],
                upgrades: Some(Arc::new(Loopback { refuse: false })),
            };
            accept_stream(a, Link::Bluetooth, &local).await.unwrap()
        });
        let local = Local {
            endpoint_id: *b"CLNT",
            endpoint_info: vec![2; 4],
            upgrades: Some(Arc::new(Loopback { refuse })),
        };
        let client = connect_stream(b, Link::Bluetooth, &local).await.unwrap();
        let (server, remote) = server.await.unwrap();
        assert_eq!(remote.mediums, vec![BwuMedium::WifiLan, BwuMedium::Bluetooth]);
        (client, server)
    }

    async fn expect_bytes(c: &mut Connection, want: &[u8]) {
        match tokio::time::timeout(Duration::from_secs(5), c.recv()).await.unwrap().unwrap() {
            Event::Bytes { data, .. } => assert_eq!(data, want),
            e => panic!("unexpected {e:?}"),
        }
    }

    #[tokio::test]
    async fn upgrades_to_another_medium_mid_connection() {
        let _ = tracing_subscriber::fmt().with_env_filter("nearcast=debug").with_test_writer().try_init();
        let (mut client, mut server) = pair_over_bluetooth(false).await;
        // Payloads keep flowing, in order, across the switch.
        for i in 0..20u8 {
            client.sender().send_bytes(vec![i; 3]).await.unwrap();
            server.sender().send_bytes(vec![i; 5]).await.unwrap();
        }
        for i in 0..20u8 {
            expect_bytes(&mut server, &[i; 3]).await;
            expect_bytes(&mut client, &[i; 5]).await;
        }
        for _ in 0..50 {
            if client.medium() == BwuMedium::WifiLan && server.medium() == BwuMedium::WifiLan {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(client.medium(), BwuMedium::WifiLan);
        assert_eq!(server.medium(), BwuMedium::WifiLan);
        assert_eq!(client.sender().chunk_size(), CHUNK_SIZE);
        client.sender().send_bytes(b"after".to_vec()).await.unwrap();
        expect_bytes(&mut server, b"after").await;
        server.sender().send_bytes(b"back".to_vec()).await.unwrap();
        expect_bytes(&mut client, b"back").await;
        client.close().await;
        assert!(matches!(server.recv().await.unwrap(), Event::Disconnected));
    }

    #[tokio::test]
    async fn stays_on_the_old_medium_when_the_peer_cant_join() {
        let (client, mut server) = pair_over_bluetooth(true).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(client.medium(), BwuMedium::Bluetooth);
        assert_eq!(server.medium(), BwuMedium::Bluetooth);
        client.sender().send_bytes(b"still here".to_vec()).await.unwrap();
        expect_bytes(&mut server, b"still here").await;
    }
}
