//! Bandwidth upgrade: moving an established connection to a faster medium.
//!
//! This follows Nearby Connections' BwuManager. The side that accepted the
//! connection starts the upgrade: it hosts a medium the other side listed in
//! its connection request and sends UPGRADE_PATH_AVAILABLE on the current
//! channel. The other side joins the medium, opens a new channel and sends
//! CLIENT_INTRODUCTION on it in the clear, which the host answers with
//! CLIENT_INTRODUCTION_ACK. Both sides then send LAST_WRITE_TO_PRIOR_CHANNEL
//! on the old channel, answer the peer's with SAFE_TO_CLOSE_PRIOR_CHANNEL,
//! and move to the new channel, which keeps the old channel's encryption
//! keys and sequence numbers. A side that can't join answers UPGRADE_FAILURE,
//! and the host tries its next medium.
//!
//! The mediums themselves (LAN sockets, Wi-Fi Direct, hotspots) are behind
//! [`Mediums`], so this module only runs the negotiation.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use futures_util::future::BoxFuture;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;
use crate::proto::connections::bandwidth_upgrade_negotiation_frame::{
    ClientIntroduction, ClientIntroductionAck, EventType as BwuEvent, UpgradePathInfo,
};
use crate::proto::connections::{
    offline_frame, v1_frame, BandwidthUpgradeNegotiationFrame, OfflineFrame, V1Frame,
};
use crate::wire::{read_frame, write_frame};

/// How long the host waits for the other side to join and connect.
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long either side waits for the introduction or its acknowledgement.
const INTRO_TIMEOUT: Duration = Duration::from_secs(10);

/// Any byte stream a medium can carry.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}
pub type BoxStream = Box<dyn Stream>;
pub type StreamRead = ReadHalf<BoxStream>;
pub type StreamWrite = WriteHalf<BoxStream>;

/// Keeps a medium up (a Wi-Fi Direct group, a joined network) until dropped.
pub type Guard = Box<dyn Send + Sync>;

/// A medium we set up for the other side to join.
pub struct Hosted {
    /// What to send in UPGRADE_PATH_AVAILABLE. The medium and the
    /// negotiation flags are filled in by the caller.
    pub info: UpgradePathInfo,
    /// Resolves to the first incoming stream on the medium.
    pub incoming: BoxFuture<'static, anyhow::Result<BoxStream>>,
    pub guard: Guard,
}

/// A medium we joined, with a stream to the host.
pub struct Joined {
    pub stream: BoxStream,
    pub guard: Guard,
}

/// The mediums this device can upgrade to.
pub trait Mediums: Send + Sync {
    /// Mediums we can host, most preferred first.
    fn hostable(&self) -> Vec<Medium>;
    /// Mediums we can join, most preferred first. These go in our
    /// connection requests.
    fn joinable(&self) -> Vec<Medium>;
    fn host(&self, medium: Medium) -> BoxFuture<'_, anyhow::Result<Hosted>>;
    fn join(&self, info: &UpgradePathInfo) -> BoxFuture<'_, anyhow::Result<Joined>>;
}

/// Commands from the reader and the upgrade task to the writer.
pub(crate) enum WriterCtl {
    /// A frame to send now on the current channel.
    Frame(Box<OfflineFrame>),
    /// A keep-alive acknowledgement, dropped while a switch is under way.
    KeepAliveAck,
    /// Send LAST_WRITE_TO_PRIOR_CHANNEL, then hold everything else until
    /// [`WriterCtl::Switch`], which moves to this stream.
    Begin(StreamWrite, Medium),
    /// The peer's LAST_WRITE arrived: send SAFE_TO_CLOSE_PRIOR_CHANNEL.
    SafeToClose,
    /// The peer's SAFE_TO_CLOSE arrived: close the old channel and move on.
    Switch,
}

/// What the reader passes on to the upgrade task.
pub(crate) enum BwuIn {
    PathAvailable(Box<UpgradePathInfo>),
    Failure,
}

/// The new channel's read half, waiting for the peer's SAFE_TO_CLOSE.
pub(crate) type ReadSlot = Arc<Mutex<Option<StreamRead>>>;

pub(crate) fn bwu_frame(
    event: BwuEvent,
    f: impl FnOnce(&mut BandwidthUpgradeNegotiationFrame),
) -> OfflineFrame {
    let mut b = BandwidthUpgradeNegotiationFrame { event_type: Some(event.into()), ..Default::default() };
    f(&mut b);
    OfflineFrame {
        version: Some(offline_frame::Version::V1.into()),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::BandwidthUpgradeNegotiation.into()),
            bandwidth_upgrade_negotiation: Some(b),
            ..Default::default()
        }),
    }
}

/// Converts a medium number from a connection request.
pub fn medium_from_i32(m: i32) -> Option<Medium> {
    Medium::try_from(m).ok().filter(|m| *m != Medium::UnknownMedium)
}

/// What the upgrade task needs to know about this connection.
pub(crate) struct Task {
    pub mediums: Arc<dyn Mediums>,
    /// Our endpoint ID, sent in CLIENT_INTRODUCTION when we join.
    pub endpoint_id: String,
    /// Set when we accepted the connection: the peer's endpoint ID and the
    /// mediums from its connection request. We then start the upgrade.
    pub host_for: Option<(String, Vec<Medium>)>,
    /// The medium the connection is on now.
    pub current: Medium,
    pub ctl: mpsc::UnboundedSender<WriterCtl>,
    pub slot: ReadSlot,
    pub rx: mpsc::UnboundedReceiver<BwuIn>,
    pub cancel: CancellationToken,
}

impl Task {
    pub async fn run(mut self) {
        let cancel = self.cancel.clone();
        tokio::select! {
            _ = cancel.cancelled() => {}
            guard = self.negotiate() => {
                // Keep the medium up for the rest of the connection.
                if let Some(guard) = guard {
                    cancel.cancelled().await;
                    drop(guard);
                }
            }
        }
    }

    /// Runs upgrades until one succeeds; returns its guard. Never returns
    /// otherwise (the caller's cancellation ends it).
    async fn negotiate(&mut self) -> Option<Guard> {
        if let Some((peer, theirs)) = self.host_for.take() {
            let ours = self.mediums.hostable();
            let candidates: Vec<Medium> = ours
                .into_iter()
                .filter(|m| theirs.contains(m) && *m != self.current)
                .collect();
            tracing::debug!("peer can join {theirs:?}; trying to host {candidates:?}");
            for m in candidates {
                match self.host(m, &peer).await {
                    Ok(guard) => return Some(guard),
                    Err(e) => tracing::info!("upgrade to {m:?} failed: {e:#}"),
                }
            }
        }
        // Whether or not we host, the peer may offer a path for us to join.
        loop {
            match self.rx.recv().await {
                Some(BwuIn::PathAvailable(info)) => match self.join(&info).await {
                    Ok(guard) => return Some(guard),
                    Err(e) => {
                        tracing::info!("can't join {:?}: {e:#}", info.medium());
                        let _ = self.ctl.send(WriterCtl::Frame(Box::new(bwu_frame(BwuEvent::UpgradeFailure, |f| {
                            f.upgrade_path_info = Some(*info)
                        }))));
                    }
                },
                Some(BwuIn::Failure) => {}
                None => std::future::pending::<()>().await,
            }
        }
    }

    async fn host(&mut self, medium: Medium, peer: &str) -> anyhow::Result<Guard> {
        let hosted = self.mediums.host(medium).await?;
        let mut info = hosted.info;
        info.medium = Some(medium.into());
        info.supports_disabling_encryption = Some(false);
        info.supports_client_introduction_ack = Some(true);
        tracing::info!("offering an upgrade to {medium:?}");
        self.ctl
            .send(WriterCtl::Frame(Box::new(bwu_frame(BwuEvent::UpgradePathAvailable, |f| {
                f.upgrade_path_info = Some(info)
            }))))
            .map_err(|_| anyhow::anyhow!("connection closed"))?;

        let incoming = hosted.incoming;
        tokio::pin!(incoming);
        let deadline = tokio::time::sleep(JOIN_TIMEOUT);
        tokio::pin!(deadline);
        let mut stream = loop {
            tokio::select! {
                s = &mut incoming => break s?,
                _ = &mut deadline => bail!("the other device didn't connect"),
                m = self.rx.recv() => match m {
                    Some(BwuIn::Failure) => bail!("the other device couldn't join"),
                    Some(BwuIn::PathAvailable(_)) => tracing::debug!("ignoring the peer's own upgrade offer while hosting"),
                    None => bail!("connection closed"),
                },
            }
        };

        let intro = tokio::time::timeout(INTRO_TIMEOUT, read_bwu(&mut stream))
            .await
            .context("no client introduction")??;
        if intro.event_type() != BwuEvent::ClientIntroduction {
            bail!("expected a client introduction, got {:?}", intro.event_type());
        }
        let id = intro.client_introduction.unwrap_or_default().endpoint_id.unwrap_or_default();
        if id != peer {
            bail!("client introduction from {id:?}, expected {peer:?}");
        }
        let ack = bwu_frame(BwuEvent::ClientIntroductionAck, |f| {
            f.client_introduction_ack = Some(ClientIntroductionAck {})
        });
        write_frame(&mut stream, &ack.encode_to_vec()).await?;
        self.install(stream, medium)?;
        Ok(hosted.guard)
    }

    async fn join(&mut self, info: &UpgradePathInfo) -> anyhow::Result<Guard> {
        let medium = info.medium();
        if !self.mediums.joinable().contains(&medium) {
            bail!("not a medium we can join");
        }
        tracing::info!("joining the offered {medium:?} upgrade");
        let joined = tokio::time::timeout(JOIN_TIMEOUT, self.mediums.join(info))
            .await
            .context("timed out joining")??;
        let mut stream = joined.stream;
        let intro = bwu_frame(BwuEvent::ClientIntroduction, |f| {
            f.client_introduction = Some(ClientIntroduction {
                endpoint_id: Some(self.endpoint_id.clone()),
                supports_disabling_encryption: Some(false),
            })
        });
        write_frame(&mut stream, &intro.encode_to_vec()).await?;
        if info.supports_client_introduction_ack() {
            let ack = tokio::time::timeout(INTRO_TIMEOUT, read_bwu(&mut stream))
                .await
                .context("no client introduction acknowledgement")??;
            if ack.event_type() != BwuEvent::ClientIntroductionAck {
                bail!("expected a client introduction acknowledgement, got {:?}", ack.event_type());
            }
        }
        self.install(stream, medium)?;
        Ok(joined.guard)
    }

    /// Hands the new channel to the reader and writer and starts the switch.
    fn install(&self, stream: BoxStream, medium: Medium) -> anyhow::Result<()> {
        let (r, w) = tokio::io::split(stream);
        *self.slot.lock().unwrap() = Some(r);
        self.ctl
            .send(WriterCtl::Begin(w, medium))
            .map_err(|_| anyhow::anyhow!("connection closed"))
    }
}

/// Reads one unencrypted bandwidth upgrade frame from a new channel.
async fn read_bwu(stream: &mut BoxStream) -> anyhow::Result<BandwidthUpgradeNegotiationFrame> {
    let frame = OfflineFrame::decode(&*read_frame(stream).await?)?;
    frame
        .v1
        .and_then(|v| v.bandwidth_upgrade_negotiation)
        .context("expected a bandwidth upgrade frame")
}
