//! The per-user daemon: owns the listening socket and mDNS presence, runs
//! transfers and serves front ends over [`crate::ipc`].

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::bluetooth::{self, Bluetooth};
use crate::connection::{self, Link, Local};
use crate::mediums::Available;
use crate::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;
use crate::upgrade::Mediums;
use crate::endpoint::{
    boot_millis, decode_endpoint_info, encode_endpoint_info, load_endpoint_id, random_endpoint_id, save_endpoint_id,
    DeviceType,
};
use crate::ipc::{self, Device, Direction, Message, Request, Route, TextInfo, Transfer, TransferState, WifiInfo};
use crate::mdns::{Change, Mdns};
use crate::share::{self, FileEntry, Update};

/// How long `send` looks for a device it hasn't seen yet.
const FIND_TIMEOUT: Duration = Duration::from_secs(10);
// Workaround for https://github.com/bluez/bluez/issues/2850: right after
// the adapter powers on (e.g. on resume), bluetoothd can accept
// RegisterAdvertisement and never reply, which would leave us invisible
// until the next adapter change. Bound the wait and retry with backoff.
// Remove this (timeout and retry) once that bug is fixed in the BlueZ
// versions we support.
/// The longest shutdown waits for transfers to send their CANCEL.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const ADVERTISE_TIMEOUT: Duration = Duration::from_secs(10);
const ADVERTISE_RETRY_MIN: Duration = Duration::from_secs(2);
const ADVERTISE_RETRY_MAX: Duration = Duration::from_secs(60);

pub struct Config {
    pub name: String,
    pub download_dir: PathBuf,
    pub visible: bool,
    pub port: u16,
    /// Advertise and discover on the local network (mDNS). Off means
    /// Bluetooth only.
    pub lan: bool,
    /// Mediums connections may be upgraded to, most preferred first.
    pub upgrades: Vec<Medium>,
}

struct Entry {
    info: Transfer,
    cancel: CancellationToken,
    decision: Option<oneshot::Sender<bool>>,
}

struct State {
    /// Keyed by mDNS full name.
    devices: HashMap<String, Device>,
    transfers: HashMap<String, Entry>,
    discover_refs: usize,
    /// Stops the Bluetooth scan.
    bt_discovery: Option<CancellationToken>,
    visible: bool,
    mdns: Option<Mdns>,
}

struct Daemon {
    cfg: Config,
    local: Local,
    port: u16,
    bt: Option<Arc<Bluetooth>>,
    state: Mutex<State>,
    events: broadcast::Sender<Message>,
    /// Visibility, followed by the Bluetooth presence task.
    visible_tx: tokio::sync::watch::Sender<bool>,
    /// Transfer tasks, so shutdown can wait for them to tell their peers.
    tasks: TaskTracker,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", cfg.port)).await.context("opening the transfer port")?;
    let port = listener.local_addr()?.port();
    let endpoint_id = load_endpoint_id(&endpoint_id_path(), boot_millis()).unwrap_or_else(random_endpoint_id);
    let upgrades: Option<Arc<dyn Mediums>> =
        (!cfg.upgrades.is_empty()).then(|| Arc::new(Available::new(cfg.upgrades.clone())) as _);
    let local = Local { endpoint_id, endpoint_info: encode_endpoint_info(DeviceType::Laptop, &cfg.name), upgrades };
    let ipc = bind_ipc().await?;
    let visible = cfg.visible;
    let bt = match Bluetooth::new().await {
        Ok(b) => {
            tracing::info!("using Bluetooth adapter {}", b.adapter_name());
            Some(Arc::new(b))
        }
        Err(e) => {
            tracing::warn!("Bluetooth unavailable: {e:#}");
            None
        }
    };
    let d = Arc::new(Daemon {
        cfg,
        local,
        port,
        bt,
        state: Mutex::new(State {
            devices: HashMap::new(),
            transfers: HashMap::new(),
            discover_refs: 0,
            bt_discovery: None,
            visible: false,
            mdns: Some(Mdns::new()?),
        }),
        events: broadcast::channel(256).0,
        visible_tx: tokio::sync::watch::channel(false).0,
        tasks: TaskTracker::new(),
    });
    if let Some(bt) = d.bt.clone() {
        tokio::spawn(bt.clone().monitor());
        tokio::spawn(d.clone().bluetooth_presence(bt));
    }
    if visible {
        d.set_visible(true)?;
    }
    tracing::info!(
        "\"{}\" ({}) listening on port {port}, saving to {}",
        d.cfg.name,
        String::from_utf8_lossy(&endpoint_id),
        d.cfg.download_dir.display()
    );

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((sock, peer)) => {
                    tracing::info!("connection from {peer}");
                    let d2 = d.clone();
                    d.tasks.spawn(async move {
                        let d = d2;
                        match connection::accept(sock, &d.local).await {
                            Ok((conn, remote)) => d.incoming(conn, remote).await,
                            Err(e) => tracing::warn!("incoming connection failed: {e:#}"),
                        }
                    });
                }
                Err(e) => tracing::warn!("accept: {e}"),
            },
            r = ipc.accept() => match r {
                Ok((sock, _)) => { tokio::spawn(d.clone().serve(sock)); }
                Err(e) => tracing::warn!("ipc accept: {e}"),
            },
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
        }
    }

    tracing::info!("shutting down");
    let mdns = {
        let mut st = d.state.lock().unwrap();
        for e in st.transfers.values() {
            e.cancel.cancel();
        }
        if st.visible
            && let Err(e) = save_endpoint_id(&endpoint_id_path(), &d.local.endpoint_id, boot_millis())
        {
            tracing::debug!("saving the endpoint ID: {e}");
        }
        st.mdns.take()
    };
    if let Some(m) = mdns {
        m.shutdown().await;
    }
    // Let the cancelled transfers send their CANCEL and linger (see
    // share::CANCEL_LINGER) so phones show a cancel rather than a failure.
    // A lingering connection ends as soon as the peer hangs up; none is
    // waited for longer than SHUTDOWN_GRACE.
    d.tasks.close();
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, d.tasks.wait()).await;
    let _ = std::fs::remove_file(ipc::socket_path());
    Ok(())
}

/// Where a stopping daemon leaves its endpoint ID for a quick restart.
fn endpoint_id_path() -> std::path::PathBuf {
    ipc::socket_path().with_file_name("nearcast-endpoint")
}

async fn bind_ipc() -> anyhow::Result<UnixListener> {
    let path = ipc::socket_path();
    if UnixStream::connect(&path).await.is_ok() {
        bail!("nearcastd is already running ({})", path.display());
    }
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

fn new_id() -> String {
    format!("{:06x}", rand::rng().random_range(0..0x100_0000u32))
}

impl Daemon {
    fn emit(&self, m: Message) {
        let _ = self.events.send(m);
    }

    fn set_visible(&self, visible: bool) -> anyhow::Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.visible == visible {
            return Ok(());
        }
        let mdns = st.mdns.as_mut().context("shutting down")?;
        // Bluetooth follows visible_tx (see bluetooth_presence).
        if self.cfg.lan {
            if visible {
                mdns.advertise(&self.local.endpoint_id, &self.local.endpoint_info, self.port)?;
            } else {
                mdns.withdraw();
            }
        }
        st.visible = visible;
        self.visible_tx.send_replace(visible);
        Ok(())
    }

    fn start_discovery(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut st = self.state.lock().unwrap();
        st.discover_refs += 1;
        if st.discover_refs > 1 {
            return Ok(());
        }
        let mdns = st.mdns.as_ref().context("shutting down")?;
        let rx = if self.cfg.lan { Some(mdns.browse(self.local.endpoint_id)?) } else { None };
        if let Some(bt) = self.bt.clone() {
            let stop = CancellationToken::new();
            st.bt_discovery = Some(stop.clone());
            tokio::spawn(self.clone().bluetooth_discovery(bt, stop));
        }
        let Some(mut rx) = rx else {
            return Ok(());
        };
        let d = self.clone();
        tokio::spawn(async move {
            while let Some(change) = rx.recv().await {
                let mut st = d.state.lock().unwrap();
                if st.discover_refs == 0 {
                    break;
                }
                match change {
                    Change::Found(f) => {
                        let dev = Device {
                            id: f.endpoint_id,
                            name: f.name,
                            device_type: f.device_type,
                            route: Route::WifiLan(f.addr),
                        };
                        st.devices.insert(f.fullname, dev.clone());
                        d.emit(Message::DeviceFound { device: dev });
                    }
                    Change::Lost { fullname } => {
                        if let Some(dev) = st.devices.remove(&fullname) {
                            d.emit(Message::DeviceLost { id: dev.id });
                        }
                    }
                }
            }
        });
        Ok(())
    }

    fn stop_discovery(&self) {
        let mut st = self.state.lock().unwrap();
        st.discover_refs = st.discover_refs.saturating_sub(1);
        if st.discover_refs == 0 {
            if let Some(m) = &st.mdns
                && self.cfg.lan
            {
                m.stop_browse();
            }
            if let Some(stop) = st.bt_discovery.take() {
                stop.cancel();
            }
            st.devices.clear();
        }
    }

    async fn bluetooth_discovery(self: Arc<Self>, bt: Arc<Bluetooth>, stop: CancellationToken) {
        let mut rx = match bt.discover().await {
            Ok(rx) => rx,
            Err(e) => {
                tracing::warn!("Bluetooth discovery: {e:#}");
                return;
            }
        };
        loop {
            let change = tokio::select! {
                _ = stop.cancelled() => break,
                c = rx.recv() => match c { Some(c) => c, None => break },
            };
            let mut st = self.state.lock().unwrap();
            match change {
                bluetooth::Change::Found(f) => {
                    tracing::debug!("found {} ({}) over Bluetooth at {}", f.name, f.endpoint_id, f.mac);
                    let dev = Device {
                        id: f.endpoint_id,
                        name: f.name,
                        device_type: f.device_type,
                        route: Route::Bluetooth(f.mac.to_string()),
                    };
                    st.devices.insert(format!("bt/{}", f.ble_addr), dev.clone());
                    self.emit(Message::DeviceFound { device: dev });
                }
                bluetooth::Change::Lost { ble_addr } => {
                    if let Some(dev) = st.devices.remove(&format!("bt/{ble_addr}")) {
                        self.emit(Message::DeviceLost { id: dev.id });
                    }
                }
            }
        }
    }

    /// Finds a device by ID or (case-insensitive) name, preferring Wi-Fi
    /// when it was seen over both.
    fn lookup(&self, to: &str) -> anyhow::Result<Option<Device>> {
        let st = self.state.lock().unwrap();
        let mut best: HashMap<&str, &Device> = HashMap::new();
        for d in st.devices.values().filter(|d| d.id == to || d.name.eq_ignore_ascii_case(to)) {
            let e = best.entry(d.id.as_str()).or_insert(d);
            if matches!(d.route, Route::WifiLan(_)) {
                *e = d;
            }
        }
        if let Some(d) = best.get(to) {
            return Ok(Some((*d).clone()));
        }
        let matches: Vec<_> = best.into_values().collect();
        match matches.as_slice() {
            [] => Ok(None),
            [d] => Ok(Some((*d).clone())),
            many => bail!(
                "several devices are called \"{to}\"; use an ID: {}",
                many.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    async fn find(self: &Arc<Self>, to: &str) -> anyhow::Result<Device> {
        let mut events = self.events.subscribe();
        self.start_discovery()?;
        let found = tokio::time::timeout(FIND_TIMEOUT, async {
            loop {
                if let Some(d) = self.lookup(to)? {
                    return Ok(d);
                }
                match events.recv().await {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await;
        self.stop_discovery();
        found.unwrap_or_else(|_| bail!("no device called \"{to}\" found nearby"))
    }

    fn add_transfer(&self, info: Transfer, decision: Option<oneshot::Sender<bool>>) -> CancellationToken {
        let cancel = CancellationToken::new();
        self.emit(Message::Transfer { transfer: info.clone() });
        let mut st = self.state.lock().unwrap();
        st.transfers.insert(info.id.clone(), Entry { info, cancel: cancel.clone(), decision });
        cancel
    }

    /// Applies a transfer's updates to its entry and broadcasts them.
    async fn relay(self: Arc<Self>, id: String, mut rx: mpsc::UnboundedReceiver<Update>) {
        while let Some(u) = rx.recv().await {
            let mut st = self.state.lock().unwrap();
            let Some(e) = st.transfers.get_mut(&id) else { return };
            let t = &mut e.info;
            match u {
                Update::Connected { pin } => t.pin = Some(pin),
                Update::WaitingForAccept => t.state = TransferState::WaitingForAccept,
                Update::Incoming { peer_name, peer_type, pin, files, texts, wifi } => {
                    t.peer = peer_name;
                    t.peer_type = peer_type;
                    t.pin = Some(pin);
                    t.bytes_total = files.iter().map(|f| f.size).sum();
                    t.files = files;
                    t.texts = texts
                        .into_iter()
                        .map(|o| TextInfo { kind: o.kind, title: o.title, content: None })
                        .collect();
                    t.wifi = wifi
                        .into_iter()
                        .map(|o| WifiInfo { ssid: o.ssid, security: o.security, password: None, hidden: false })
                        .collect();
                    t.state = TransferState::AwaitingDecision;
                }
                Update::Transferring => t.state = TransferState::Transferring,
                Update::Progress { done, total } => {
                    t.bytes_done = done;
                    t.bytes_total = total;
                }
                Update::Finished { saved, texts, wifi } => {
                    t.state = TransferState::Finished;
                    t.bytes_done = t.bytes_total;
                    t.saved = saved;
                    for (info, content) in t.texts.iter_mut().zip(texts) {
                        info.content = Some(content);
                    }
                    for (info, got) in t.wifi.iter_mut().zip(wifi) {
                        info.password = Some(got.password);
                        info.hidden = got.hidden;
                    }
                }
                Update::Rejected => t.state = TransferState::Rejected,
                Update::Cancelled { by_peer } => {
                    t.state = TransferState::Cancelled;
                    if by_peer {
                        t.error = Some("cancelled by the other device".into());
                    }
                }
                Update::Failed(msg) => {
                    t.state = TransferState::Failed;
                    t.error = Some(msg);
                }
            }
            if t.state.is_final() {
                e.decision = None;
                tracing::info!("transfer {id}: {:?}{}", t.state, t.error.as_ref().map(|e| format!(": {e}")).unwrap_or_default());
            }
            self.emit(Message::Transfer { transfer: e.info.clone() });
        }
    }

    /// Advertises over BLE and accepts RFCOMM connections while visible,
    /// setting up again whenever the adapter goes away, comes back or
    /// changes power.
    async fn bluetooth_presence(self: Arc<Self>, bt: Arc<Bluetooth>) {
        let mut visible = self.visible_tx.subscribe();
        let mut adapter = bt.state();
        let mut retry = ADVERTISE_RETRY_MIN;
        // Waits for either input to change; false once visibility is gone.
        async fn changed(
            visible: &mut tokio::sync::watch::Receiver<bool>,
            adapter: &mut tokio::sync::watch::Receiver<crate::bluetooth::AdapterState>,
        ) -> bool {
            tokio::select! {
                r = visible.changed() => r.is_ok(),
                // Bluetooth owns the sender, so this only fails at shutdown.
                r = adapter.changed() => r.is_ok(),
            }
        }
        loop {
            let want = *visible.borrow_and_update();
            let up = adapter.borrow_and_update().up;
            if !want || !up {
                if !changed(&mut visible, &mut adapter).await {
                    return;
                }
                continue;
            }
            let advertise = bt.advertise(&self.local.endpoint_id, &self.local.endpoint_info);
            let res = match tokio::time::timeout(ADVERTISE_TIMEOUT, advertise).await {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("bluetoothd did not answer within {ADVERTISE_TIMEOUT:?}")),
            };
            let (presence, mut incoming) = match res {
                Ok(p) => {
                    retry = ADVERTISE_RETRY_MIN;
                    p
                }
                Err(e) => {
                    // Retry with backoff (see ADVERTISE_TIMEOUT), or sooner
                    // on the next visibility or adapter change.
                    tracing::warn!("Bluetooth advertising: {e:#}; retrying in {retry:?}");
                    tokio::select! {
                        alive = changed(&mut visible, &mut adapter) => {
                            if !alive {
                                return;
                            }
                            retry = ADVERTISE_RETRY_MIN;
                        }
                        _ = tokio::time::sleep(retry) => {
                            retry = (retry * 2).min(ADVERTISE_RETRY_MAX);
                        }
                    }
                    continue;
                }
            };
            loop {
                tokio::select! {
                    r = visible.changed() => {
                        if r.is_err() || !*visible.borrow() {
                            break;
                        }
                    }
                    _ = adapter.changed() => break,
                    Some((stream, peer)) = incoming.recv() => {
                        let d = self.clone();
                        self.tasks.spawn(async move {
                            match connection::accept_stream(stream, Link::Bluetooth, &d.local).await {
                                Ok((conn, remote)) => d.incoming(conn, remote).await,
                                Err(e) => tracing::warn!("Bluetooth connection from {peer} failed: {e:#}"),
                            }
                        });
                    }
                }
            }
            drop(presence);
            tracing::info!("stopped Bluetooth advertising");
        }
    }

    async fn incoming(self: Arc<Self>, conn: connection::Connection, remote: connection::Remote) {
        let (peer_type, peer) = decode_endpoint_info(&remote.endpoint_info).unwrap_or((DeviceType::Unknown, None));
        let id = new_id();
        let (dec_tx, dec_rx) = oneshot::channel();
        let cancel = self.add_transfer(
            Transfer {
                id: id.clone(),
                direction: Direction::Incoming,
                peer: peer.unwrap_or_else(|| "Unknown device".into()),
                peer_type,
                state: TransferState::Connecting,
                pin: Some(conn.pin().to_owned()),
                files: Vec::new(),
                texts: Vec::new(),
                wifi: Vec::new(),
                bytes_done: 0,
                bytes_total: 0,
                saved: Vec::new(),
                error: None,
            },
            Some(dec_tx),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(self.clone().relay(id, rx));
        let inc = share::Incoming { decision: dec_rx, download_dir: self.cfg.download_dir.clone() };
        share::receive(conn, remote, inc, share::Control { cancel, updates: tx, lingers: self.tasks.clone() }).await;
        let _ = relay.await;
    }

    async fn start_send(
        self: &Arc<Self>,
        to: &str,
        files: Vec<PathBuf>,
        text: Option<String>,
    ) -> anyhow::Result<String> {
        if files.is_empty() && text.is_none() {
            bail!("nothing to send");
        }
        let mut entries = Vec::new();
        for f in &files {
            if !f.is_absolute() {
                bail!("{} is not an absolute path", f.display());
            }
            let md = std::fs::metadata(f).with_context(|| format!("{}", f.display()))?;
            if !md.is_file() {
                bail!("{} is not a regular file", f.display());
            }
            let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            entries.push(FileEntry { name, size: md.len() });
        }
        let dev = match self.lookup(to)? {
            Some(d) => d,
            None => self.find(to).await?,
        };
        let id = new_id();
        let text_info = text.as_ref().map(|t| TextInfo {
            kind: share::text_kind(t),
            title: t.chars().take(100).collect(),
            content: Some(t.clone()),
        });
        let bytes_total = entries.iter().map(|f| f.size).sum::<u64>() + text.as_ref().map_or(0, |t| t.len() as u64);
        let cancel = self.add_transfer(
            Transfer {
                id: id.clone(),
                direction: Direction::Outgoing,
                peer: dev.name.clone(),
                peer_type: dev.device_type,
                state: TransferState::Connecting,
                pin: None,
                files: entries,
                texts: text_info.into_iter().collect(),
                wifi: Vec::new(),
                bytes_done: 0,
                bytes_total,
                saved: Vec::new(),
                error: None,
            },
            None,
        );
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(self.clone().relay(id.clone(), rx));
        let d = self.clone();
        self.tasks.spawn(async move {
            let d2 = d.clone();
            let connect = Box::pin(async move {
                match dev.route {
                    Route::WifiLan(addr) => connection::connect(addr, &d2.local).await,
                    Route::Bluetooth(mac) => {
                        let bt = d2.bt.as_ref().context("Bluetooth is unavailable")?;
                        let stream = bt.connect(mac.parse()?).await?;
                        connection::connect_stream(stream, Link::Bluetooth, &d2.local).await
                    }
                }
            });
            let req = share::Outgoing { connect, files, text };
            share::send(req, share::Control { cancel, updates: tx, lingers: d.tasks.clone() }).await;
        });
        Ok(id)
    }

    fn decide(&self, id: &str, accept: bool) -> anyhow::Result<()> {
        let mut st = self.state.lock().unwrap();
        let e = st.transfers.get_mut(id).with_context(|| format!("no transfer {id}"))?;
        if e.info.state != TransferState::AwaitingDecision {
            bail!("transfer {id} isn't waiting for a decision");
        }
        let tx = e.decision.take().context("already decided")?;
        let _ = tx.send(accept);
        Ok(())
    }

    fn cancel(&self, id: &str) -> anyhow::Result<()> {
        let st = self.state.lock().unwrap();
        let e = st.transfers.get(id).with_context(|| format!("no transfer {id}"))?;
        if e.info.state.is_final() {
            bail!("transfer {id} is already over");
        }
        e.cancel.cancel();
        Ok(())
    }

    fn status(&self) -> Message {
        let st = self.state.lock().unwrap();
        let mut transfers: Vec<_> = st.transfers.values().map(|e| e.info.clone()).collect();
        transfers.sort_by(|a, b| a.id.cmp(&b.id));
        Message::Status {
            name: self.cfg.name.clone(),
            endpoint_id: String::from_utf8_lossy(&self.local.endpoint_id).into_owned(),
            visible: st.visible,
            port: self.port,
            download_dir: self.cfg.download_dir.clone(),
            transfers,
        }
    }

    /// Serves one front-end connection.
    async fn serve(self: Arc<Self>, sock: UnixStream) {
        let (r, mut w) = sock.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                let mut line = serde_json::to_vec(&m).expect("messages serialize");
                line.push(b'\n');
                if w.write_all(&line).await.is_err() {
                    break;
                }
            }
        });
        let mut forwarder: Option<tokio::task::JoinHandle<()>> = None;
        let mut discovering = false;
        let subscribe = |forwarder: &mut Option<tokio::task::JoinHandle<()>>| {
            if forwarder.is_none() {
                let mut events = self.events.subscribe();
                let tx = tx.clone();
                *forwarder = Some(tokio::spawn(async move {
                    loop {
                        match events.recv().await {
                            Ok(m) => {
                                if tx.send(m).is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => break,
                        }
                    }
                }));
            }
        };

        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let req: Request = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Message::Error { message: format!("bad request: {e}") });
                    continue;
                }
            };
            let reply = match req {
                Request::Status => Ok(self.status()),
                Request::Watch => {
                    subscribe(&mut forwarder);
                    Ok(Message::Ok)
                }
                Request::Discover => {
                    subscribe(&mut forwarder);
                    if !discovering {
                        match self.start_discovery() {
                            Ok(()) => discovering = true,
                            Err(e) => {
                                let _ = tx.send(Message::Error { message: format!("{e:#}") });
                                continue;
                            }
                        }
                    }
                    let _ = tx.send(Message::Ok);
                    let devices: Vec<_> = self.state.lock().unwrap().devices.values().cloned().collect();
                    for device in devices {
                        let _ = tx.send(Message::DeviceFound { device });
                    }
                    continue;
                }
                Request::Send { to, files, text } => {
                    subscribe(&mut forwarder);
                    self.start_send(&to, files, text).await.map(|id| Message::Started { id })
                }
                Request::Accept { id } => self.decide(&id, true).map(|_| Message::Ok),
                Request::Reject { id } => self.decide(&id, false).map(|_| Message::Ok),
                Request::Cancel { id } => self.cancel(&id).map(|_| Message::Ok),
                Request::SetVisible { visible } => self.set_visible(visible).map(|_| Message::Ok),
            };
            let _ = tx.send(reply.unwrap_or_else(|e| Message::Error { message: format!("{e:#}") }));
        }

        if discovering {
            self.stop_discovery();
        }
        if let Some(f) = forwarder {
            f.abort();
        }
        drop(tx);
        let _ = writer.await;
    }
}
