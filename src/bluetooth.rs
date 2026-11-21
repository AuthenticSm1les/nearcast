//! Bluetooth for Nearby Connections: finding receivers and connecting to
//! them (level 1), and advertising and accepting connections as a receiver
//! (level 2).
//!
//! A receiver puts its whole advertisement in an extended BLE advertisement
//! (only seen by Bluetooth 5 scanners). Without extended advertising it puts a
//! small "regular" BLE advertisement header in the
//! 0xFEF3 (Copresence) service data and serves the full advertisement from
//! GATT characteristics, one per slot. That advertisement carries the endpoint
//! info (device name) and the Bluetooth Classic MAC, which we then connect to
//! over RFCOMM using the service's UUID. Frames on RFCOMM are the same
//! length-prefixed frames as on TCP.
//!
//! Formats follow google/nearby: connections/implementation/mediums/ble_v2/
//! (ble_advertisement_header, ble_advertisement) and the PCP-level
//! ble_advertisement.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use bluer::rfcomm::{ConnectRequest, Profile, ReqError, Stream};
use bluer::{
    Adapter, AdapterEvent, AdapterProperty, Address, DiscoveryFilter, DiscoveryTransport, Session, SessionEvent, Uuid,
};
use futures_util::{stream, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::endpoint::{decode_endpoint_info, DeviceType, PCP_P2P_POINT_TO_POINT, SERVICE_ID, SERVICE_ID_HASH};
use sha2::{Digest, Sha256};

/// Java's `UUID.nameUUIDFromBytes("NearbySharing")`: the RFCOMM service UUID.
pub const SERVICE_UUID: Uuid = Uuid::from_u128(0xa82efa21_ae5c_3dde_9bbc_f16da7b16c5a);
/// The Copresence service carrying Nearby BLE advertisements.
const COPRESENCE_UUID: Uuid = Uuid::from_u128(0x0000fef3_0000_1000_8000_00805f9b34fb);

const GATT_READ_TIMEOUT: Duration = Duration::from_secs(15);
const RFCOMM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const ADVERTISEMENT_HEADER_LEN: usize = 17;
/// GATT characteristic for advertisement slot 0.
const ADVERTISEMENT_SLOT0_UUID: Uuid = Uuid::from_u128(0x00000000_0000_3000_8000_000000000000);
/// AD overhead around the service data: flags (3) + length/type/UUID16 (4).
const SERVICE_DATA_OVERHEAD: usize = 7;

/// A receiver found over BLE.
#[derive(Debug, Clone)]
pub struct Found {
    /// BLE address the advertisement came from (may be random/private).
    pub ble_addr: Address,
    pub endpoint_id: String,
    pub name: String,
    pub device_type: DeviceType,
    /// Bluetooth Classic address to connect to.
    pub mac: Address,
}

pub enum Change {
    Found(Found),
    Lost { ble_addr: Address },
}

type Waiters = Arc<Mutex<HashMap<Address, oneshot::Sender<ConnectRequest>>>>;
type Server = Arc<Mutex<Option<mpsc::UnboundedSender<(Stream, Address)>>>>;

pub struct Bluetooth {
    session: Session,
    adapter: Adapter,
    waiters: Waiters,
    /// Where accepted incoming connections go while we are visible.
    server: Server,
    /// Task owning our RFCOMM profile registration; aborting it unregisters.
    profile: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    state: watch::Sender<AdapterState>,
}

/// Whether the adapter can be used, and a counter that moves every time it
/// went away, came back or changed power, after which anything registered on
/// it (advertisements, GATT applications) must be set up again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterState {
    pub up: bool,
    pub epoch: u64,
}

impl Bluetooth {
    pub async fn new() -> anyhow::Result<Self> {
        let session = Session::new().await.context("connecting to BlueZ")?;
        let adapter = session.default_adapter().await.context("no Bluetooth adapter")?;
        let up = adapter.is_powered().await.unwrap_or(false);
        Ok(Self {
            session,
            adapter,
            waiters: Default::default(),
            server: Default::default(),
            profile: Default::default(),
            state: watch::channel(AdapterState { up, epoch: 0 }).0,
        })
    }

    /// Follows the adapter's state; see [`AdapterState`].
    pub fn state(&self) -> watch::Receiver<AdapterState> {
        self.state.subscribe()
    }

    fn set_up(&self, up: bool) {
        self.state.send_modify(|s| {
            s.up = up;
            s.epoch += 1;
        });
    }

    /// Tracks our adapter through power changes, removal (suspend can drop
    /// and re-create it) and bluetoothd restarts, from BlueZ's own signals.
    pub async fn monitor(self: Arc<Self>) {
        let name = self.adapter.name().to_string();
        loop {
            // bluer ends this stream when /org/bluez itself is removed, which
            // bluetoothd does as it exits; subscribing again lets us see the
            // daemon that replaces it.
            let mut session_events = match self.session.events().await {
                Ok(e) => e.boxed(),
                Err(e) => {
                    tracing::warn!("can't follow Bluetooth adapter changes: {e}");
                    return;
                }
            };
            'adapter: loop {
                // Ends when the adapter is removed; a new one is needed after
                // it comes back.
                let mut adapter_events = match self.adapter.events().await {
                    Ok(e) => e.boxed(),
                    Err(e) => {
                        tracing::debug!("adapter events: {e}");
                        stream::pending().boxed()
                    }
                };
                loop {
                    tokio::select! {
                        ev = session_events.next() => match ev {
                            Some(SessionEvent::AdapterAdded(n)) if n == name => {
                                tracing::info!("Bluetooth adapter {name} appeared");
                                self.refresh_profile().await;
                                self.set_up(self.adapter.is_powered().await.unwrap_or(false));
                                continue 'adapter;
                            }
                            Some(SessionEvent::AdapterRemoved(n)) if n == name => {
                                tracing::info!("Bluetooth adapter {name} went away");
                                self.set_up(false);
                            }
                            Some(_) => {}
                            None => break 'adapter,
                        },
                        ev = adapter_events.next() => match ev {
                            Some(AdapterEvent::PropertyChanged(AdapterProperty::Powered(up)))
                                if up != self.state.borrow().up =>
                            {
                                tracing::info!("Bluetooth adapter {name} powered {}", if up { "on" } else { "off" });
                                self.set_up(up);
                            }
                            Some(_) => {}
                            None => adapter_events = stream::pending().boxed(),
                        },
                    }
                }
            }
            tracing::info!("bluetoothd went away");
            if self.state.borrow().up {
                self.set_up(false);
            }
        }
    }

    pub fn adapter_name(&self) -> &str {
        self.adapter.name()
    }

    async fn ensure_powered(&self) -> anyhow::Result<()> {
        if !self.adapter.is_powered().await? {
            anyhow::bail!("Bluetooth is off");
        }
        Ok(())
    }

    /// Scans for receivers until the returned receiver is dropped.
    pub async fn discover(&self) -> anyhow::Result<mpsc::UnboundedReceiver<Change>> {
        self.ensure_powered().await?;
        let adapter = self.adapter.clone();
        adapter
            .set_discovery_filter(DiscoveryFilter {
                transport: DiscoveryTransport::Le,
                duplicate_data: true,
                ..Default::default()
            })
            .await?;
        let mut events = adapter.discover_devices_with_changes().await?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            // Header last resolved per BLE address, so each is read once.
            let mut seen: HashMap<Address, Vec<u8>> = HashMap::new();
            let mut found: HashMap<Address, ()> = HashMap::new();
            loop {
                let ev = tokio::select! {
                    _ = tx.closed() => break,
                    ev = events.next() => match ev { Some(ev) => ev, None => break },
                };
                let change = match ev {
                    AdapterEvent::DeviceAdded(addr) => match resolve(&adapter, addr, &mut seen).await {
                        Some(f) => {
                            found.insert(addr, ());
                            Change::Found(f)
                        }
                        None => continue,
                    },
                    AdapterEvent::DeviceRemoved(addr) => {
                        seen.remove(&addr);
                        if found.remove(&addr).is_none() {
                            continue;
                        }
                        Change::Lost { ble_addr: addr }
                    }
                    _ => continue,
                };
                if tx.send(change).is_err() {
                    break;
                }
            }
            // Dropping `events` ends our discovery session in BlueZ.
        });
        Ok(rx)
    }

    /// Registers the RFCOMM profile once, for both roles. BlueZ allows one
    /// profile per UUID; outgoing connections are matched to their waiter,
    /// the rest are incoming.
    async fn ensure_profile(&self) -> anyhow::Result<()> {
        let mut profile = self.profile.lock().await;
        if profile.is_none() {
            *profile = Some(self.register_profile().await?);
        }
        Ok(())
    }

    /// After the adapter reappears: if bluetoothd restarted it forgot our
    /// profile and registering again succeeds; if only the adapter was
    /// re-created the profile survived, and BlueZ refuses a second one for
    /// the same UUID, so we keep the one we have.
    async fn refresh_profile(&self) {
        let mut profile = self.profile.lock().await;
        if profile.is_none() {
            return;
        }
        match self.register_profile().await {
            Ok(task) => {
                tracing::info!("registered the Bluetooth profile again");
                if let Some(old) = profile.replace(task) {
                    old.abort();
                }
            }
            Err(e) => tracing::debug!("keeping the Bluetooth profile: {e:#}"),
        }
    }

    async fn register_profile(&self) -> anyhow::Result<JoinHandle<()>> {
        let mut handle = self
            .session
            .register_profile(Profile {
                uuid: SERVICE_UUID,
                name: Some(SERVICE_ID.into()),
                // Any free channel. BlueZ only listens, and lists
                // the channel in the SDP record, for custom UUIDs
                // when one is given.
                channel: Some(0),
                require_authentication: Some(false),
                require_authorization: Some(false),
                auto_connect: Some(false),
                ..Default::default()
            })
            .await
            .context(
                "registering the Quick Share Bluetooth profile \
                 (is another Quick Share app running?)",
            )?;
        let waiters = self.waiters.clone();
        let server = self.server.clone();
        Ok(tokio::spawn(async move {
            while let Some(req) = handle.next().await {
                let waiter = waiters.lock().unwrap().remove(&req.device());
                match waiter {
                    Some(tx) => {
                        if let Err(req) = tx.send(req) {
                            req.reject(ReqError::Rejected);
                        }
                    }
                    None => {
                        let peer = req.device();
                        let tx = server.lock().unwrap().clone();
                        match tx {
                            Some(tx) => match req.accept() {
                                Ok(stream) => {
                                    tracing::info!("incoming Bluetooth connection from {peer}");
                                    let _ = tx.send((stream, peer));
                                }
                                Err(e) => tracing::warn!("accepting {peer}: {e}"),
                            },
                            None => req.reject(ReqError::Rejected),
                        }
                    }
                }
            }
            tracing::warn!("Bluetooth profile closed");
        }))
    }

    /// Opens an RFCOMM connection to the Quick Share service of `mac`.
    pub async fn connect(&self, mac: Address) -> anyhow::Result<Stream> {
        self.ensure_powered().await?;
        self.ensure_profile().await?;
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(mac, tx);
        let device = self.adapter.device(mac)?;
        tracing::info!("connecting to {mac} over RFCOMM");
        let res = tokio::time::timeout(RFCOMM_CONNECT_TIMEOUT, async {
            // BlueZ answers ConnectProfile only after our profile accepted
            // the connection, so accept as soon as the request arrives.
            let accept = async {
                let req = rx.await.map_err(|_| anyhow!("no RFCOMM connection came in"))?;
                Ok::<_, anyhow::Error>(req.accept()?)
            };
            match tokio::join!(device.connect_profile(&SERVICE_UUID), accept) {
                (_, Ok(stream)) => Ok(stream),
                (Err(e), Err(_)) => Err(anyhow::Error::from(e)),
                (Ok(()), Err(e)) => Err(e),
            }
        })
        .await;
        self.waiters.lock().unwrap().remove(&mac);
        res.map_err(|_| anyhow!("timed out connecting to {mac} over Bluetooth"))?
    }
}

/// Keeps us discoverable over BLE and accepting RFCOMM connections; dropping
/// it stops both.
pub struct Presence {
    _adv: bluer::adv::AdvertisementHandle,
    _gatt: Option<bluer::gatt::local::ApplicationHandle>,
    server: Server,
}

impl Drop for Presence {
    fn drop(&mut self) {
        *self.server.lock().unwrap() = None;
    }
}

impl Bluetooth {
    /// Advertises our endpoint and starts accepting connections, which arrive
    /// on the returned receiver.
    pub async fn advertise(
        &self,
        endpoint_id: &[u8; 4],
        endpoint_info: &[u8],
    ) -> anyhow::Result<(Presence, mpsc::UnboundedReceiver<(Stream, Address)>)> {
        use bluer::adv::{Advertisement, Type};
        use bluer::gatt::local::{Application, Characteristic, CharacteristicRead, Service};

        self.ensure_powered().await?;
        self.ensure_profile().await?;
        let mac = self.adapter.address().await?;
        let value = encode_advertisement(&encode_pcp_advertisement(endpoint_id, endpoint_info, mac));
        // Workaround: bluer can't parse capabilities when BlueZ omits the TX
        // power range, so an unknown limit means "try extended, fall back to
        // legacy". Once bluer parses them, the limit alone can decide.
        let max_len = match self.adapter.supported_advertising_capabilities().await {
            Ok(Some(c)) => Some(c.max_advertisement_length as usize),
            _ => None,
        };
        // Like Chrome (BluetoothAdapterBlueZ::IsExtendedAdvertisementsAvailable):
        // the kernel lists HardwareOffload among the advertising features only
        // on controllers with extended advertising, so without it the
        // extended advertisement would just be refused. If bluetoothd doesn't
        // report features at all, try anyway.
        let has_extended = match self.adapter.supported_advertising_features().await {
            Ok(Some(f)) => f.contains(&bluer::adv::PlatformFeature::HardwareOffload),
            _ => true,
        };
        let try_extended =
            has_extended && max_len.is_none_or(|m| value.len() + SERVICE_DATA_OVERHEAD <= m);

        let extended = if try_extended {
            let r = self
                .adapter
                .advertise(Advertisement {
                    advertisement_type: Type::Broadcast,
                    service_data: [(COPRESENCE_UUID, value.clone())].into(),
                    ..Default::default()
                })
                .await;
            match r {
                Ok(adv) => {
                    tracing::info!("advertising over BLE (extended, {} bytes)", value.len());
                    Some(adv)
                }
                Err(e) => {
                    tracing::debug!("extended advertising refused: {e}");
                    None
                }
            }
        } else {
            None
        };

        let (adv, gatt) = if let Some(adv) = extended {
            (adv, None)
        } else {
            // Legacy advertising: a header pointing to a GATT slot holding the
            // advertisement.
            tracing::info!("advertising over BLE (legacy header + GATT)");
            let header = STANDARD_NO_PAD.encode(encode_advertisement_header(&value));
            let value = Arc::new(value);
            let gatt = self
                .adapter
                .serve_gatt_application(Application {
                    services: vec![Service {
                        uuid: COPRESENCE_UUID,
                        primary: true,
                        characteristics: vec![Characteristic {
                            uuid: ADVERTISEMENT_SLOT0_UUID,
                            read: Some(CharacteristicRead {
                                read: true,
                                fun: Box::new(move |req| {
                                    let v = value.clone();
                                    Box::pin(async move { Ok(v.get(req.offset as usize..).unwrap_or_default().to_vec()) })
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .await?;
            let adv = self
                .adapter
                .advertise(Advertisement {
                    advertisement_type: Type::Peripheral,
                    service_data: [(COPRESENCE_UUID, header.into_bytes())].into(),
                    ..Default::default()
                })
                .await?;
            (adv, Some(gatt))
        };
        let (tx, rx) = mpsc::unbounded_channel();
        *self.server.lock().unwrap() = Some(tx);
        Ok((Presence { _adv: adv, _gatt: gatt, server: self.server.clone() }, rx))
    }
}

/// PCP-level advertisement: version|pcp, service ID hash, endpoint ID,
/// endpoint info, Bluetooth MAC, UWB address length, extra field.
fn encode_pcp_advertisement(endpoint_id: &[u8; 4], endpoint_info: &[u8], mac: Address) -> Vec<u8> {
    let mut out = vec![PCP_P2P_POINT_TO_POINT];
    out.extend_from_slice(&SERVICE_ID_HASH);
    out.extend_from_slice(endpoint_id);
    out.push(endpoint_info.len() as u8);
    out.extend_from_slice(endpoint_info);
    out.extend_from_slice(&mac.0);
    out.push(0); // no UWB address
    out.push(0); // extra field: WebRTC not connectable
    out
}

/// Medium-level BLE advertisement, version 2, socket version 2, not fast.
fn encode_advertisement(pcp: &[u8]) -> Vec<u8> {
    let mut out = vec![(2 << 5) | (2 << 2)];
    out.extend_from_slice(&SERVICE_ID_HASH);
    out.extend_from_slice(&(pcp.len() as u32).to_be_bytes());
    out.extend_from_slice(pcp);
    out.extend_from_slice(&rand::random::<[u8; 2]>()); // device token
    out
}

/// MurmurHash3 x64 128, seed 0, low 64 bits: what Nearby's bloom filter uses.
fn murmur3_x64_128_low(data: &[u8]) -> u64 {
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;
    fn fmix(mut k: u64) -> u64 {
        k ^= k >> 33;
        k = k.wrapping_mul(0xff51afd7ed558ccd);
        k ^= k >> 33;
        k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
        k ^ (k >> 33)
    }
    let (mut h1, mut h2) = (0u64, 0u64);
    let blocks = data.len() / 16;
    for i in 0..blocks {
        let k1 = u64::from_le_bytes(data[i * 16..i * 16 + 8].try_into().unwrap());
        let k2 = u64::from_le_bytes(data[i * 16 + 8..i * 16 + 16].try_into().unwrap());
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 = h1.rotate_left(27).wrapping_add(h2).wrapping_mul(5).wrapping_add(0x52dce729);
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 = h2.rotate_left(31).wrapping_add(h1).wrapping_mul(5).wrapping_add(0x38495ab5);
    }
    let tail = &data[blocks * 16..];
    let (mut k1, mut k2) = (0u64, 0u64);
    for (i, b) in tail.iter().enumerate() {
        if i < 8 {
            k1 |= (*b as u64) << (8 * i);
        } else {
            k2 |= (*b as u64) << (8 * (i - 8));
        }
    }
    if tail.len() > 8 {
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
    }
    if !tail.is_empty() {
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    }
    let len = data.len() as u64;
    h1 ^= len;
    h2 ^= len;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix(h1);
    h2 = fmix(h2);
    h1.wrapping_add(h2)
}

/// Adds a service ID to the 10-byte bloom filter (5 hashes over 80 bits).
fn bloom_add(filter: &mut [u8; 10], s: &[u8]) {
    let h = murmur3_x64_128_low(s);
    let (h1, h2) = (h as u32 as i32, (h >> 32) as u32 as i32);
    for i in 1..=5i32 {
        let mut c = h1.wrapping_add(i.wrapping_mul(h2));
        if c < 0 {
            c = !c;
        }
        let pos = c as usize % 80;
        filter[pos / 8] |= 1 << (pos % 8);
    }
}

/// Advertisement header, version 2, not extended, one slot: bloom filter of
/// service IDs, hash of the advertisement, and no L2CAP PSM.
fn encode_advertisement_header(advertisement: &[u8]) -> [u8; ADVERTISEMENT_HEADER_LEN] {
    let mut bloom = [0u8; 10];
    bloom_add(&mut bloom, SERVICE_ID.as_bytes());
    let hash = Sha256::digest(advertisement);
    let mut out = [0u8; ADVERTISEMENT_HEADER_LEN];
    out[0] = (2 << 5) | 1;
    out[1..11].copy_from_slice(&bloom);
    out[11..15].copy_from_slice(&hash[..4]);
    out
}

/// Reads the advertisement of a device showing a Nearby header, if new.
async fn resolve(adapter: &Adapter, addr: Address, seen: &mut HashMap<Address, Vec<u8>>) -> Option<Found> {
    let device = adapter.device(addr).ok()?;
    let data = device.service_data().await.ok()??;
    let raw = data.get(&COPRESENCE_UUID)?;
    // Extended advertising carries the whole advertisement; no GATT needed.
    if let Some((endpoint_id, info, mac)) = parse_advertisement(raw) {
        let (device_type, name) = decode_endpoint_info(&info).ok()?;
        return Some(Found { ble_addr: addr, endpoint_id, name: name?, device_type, mac });
    }
    let header = decode_advertisement_header(raw)?;
    if seen.get(&addr) == Some(&header) {
        return None;
    }
    seen.insert(addr, header);

    let read = async {
        device.connect().await?;
        let mut found = None;
        'services: for service in device.services().await? {
            if service.uuid().await? != COPRESENCE_UUID {
                continue;
            }
            // One characteristic per advertisement slot.
            for c in service.characteristics().await? {
                if let Ok(v) = c.read().await
                    && let Some(p) = parse_advertisement(&v)
                {
                    found = Some(p);
                    break 'services;
                }
            }
        }
        let _ = device.disconnect().await;
        found.context("no Quick Share advertisement over GATT")
    };
    let (endpoint_id, info, mac) = match tokio::time::timeout(GATT_READ_TIMEOUT, read).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::debug!("{addr}: {e:#}");
            seen.remove(&addr);
            return None;
        }
        Err(_) => {
            tracing::debug!("{addr}: GATT read timed out");
            let _ = device.disconnect().await;
            seen.remove(&addr);
            return None;
        }
    };
    let (device_type, name) = decode_endpoint_info(&info).ok()?;
    Some(Found {
        ble_addr: addr,
        endpoint_id,
        // Hidden (contacts-only) devices carry no name; we can't show them.
        name: name?,
        device_type,
        mac,
    })
}

/// The 17-byte advertisement header (sent base64-encoded by Nearby), or None
/// for anything else such as fast advertisements.
fn decode_advertisement_header(raw: &[u8]) -> Option<Vec<u8>> {
    let header = if raw.len() == ADVERTISEMENT_HEADER_LEN {
        raw.to_vec()
    } else {
        let text = std::str::from_utf8(raw).ok()?.trim_end_matches('=');
        STANDARD_NO_PAD.decode(text).or_else(|_| URL_SAFE_NO_PAD.decode(text)).ok()?
    };
    // Version 2, at least one slot.
    (header.len() == ADVERTISEMENT_HEADER_LEN && header[0] >> 5 == 2 && header[0] & 0x0f != 0)
        .then_some(header)
}

/// Parses a medium-level BLE advertisement (version 2, not fast) wrapping a
/// PCP-level one; returns (endpoint ID, endpoint info, Bluetooth MAC).
fn parse_advertisement(v: &[u8]) -> Option<(String, Vec<u8>, Address)> {
    // version(3) | socket version(3) | fast(1) | reserved(1), hash(3), len(4), data
    if v.len() < 8 || v[0] >> 5 != 2 || v[0] & 0x02 != 0 || v[1..4] != SERVICE_ID_HASH {
        return None;
    }
    let len = u32::from_be_bytes(v[4..8].try_into().ok()?) as usize;
    let pcp = v.get(8..8 + len)?;
    // version|pcp, hash(3), endpoint ID(4), info length, info, MAC(6), ...
    if pcp.len() < 9 || pcp[0] >> 5 != 1 || pcp[1..4] != SERVICE_ID_HASH {
        return None;
    }
    let endpoint_id = std::str::from_utf8(&pcp[4..8]).ok()?.to_owned();
    let info_len = pcp[8] as usize;
    let info = pcp.get(9..9 + info_len)?.to_vec();
    let mac: [u8; 6] = pcp.get(9 + info_len..15 + info_len)?.try_into().ok()?;
    (mac != [0; 6]).then_some((endpoint_id, info, Address(mac)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::encode_endpoint_info;

    #[test]
    fn service_uuid_is_name_based_uuid_of_service_id() {
        // Java nameUUIDFromBytes: MD5, then version 3 and IETF variant bits.
        let mut h = md5_of(SERVICE_ID.as_bytes());
        h[6] = (h[6] & 0x0f) | 0x30;
        h[8] = (h[8] & 0x3f) | 0x80;
        assert_eq!(Uuid::from_bytes(h), SERVICE_UUID);
    }

    // Small MD5 so the test doesn't need another crate.
    fn md5_of(data: &[u8]) -> [u8; 16] {
        let s: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
            20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10,
            15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
        let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&((data.len() as u64) * 8).to_le_bytes());
        for chunk in msg.chunks(64) {
            let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect();
            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
            for i in 0..64 {
                let (f, g) = match i / 16 {
                    0 => ((b & c) | (!b & d), i),
                    1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                    2 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | !d), (7 * i) % 16),
                };
                let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f.rotate_left(s[i]));
            }
            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }
        let mut out = [0u8; 16];
        for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    #[test]
    fn murmur3_reference_vectors() {
        assert_eq!(murmur3_x64_128_low(b""), 0);
        assert_eq!(murmur3_x64_128_low(b"hello"), 0xcbd8a7b341bd9b02);
        assert_eq!(murmur3_x64_128_low(b"The quick brown fox jumps over the lazy dog"), 0xe34bbc7bbc071b6c);
    }

    #[test]
    fn our_advertisement_parses() {
        let info = encode_endpoint_info(DeviceType::Laptop, "laptop");
        let mac = Address([0x02, 0, 0, 0, 0, 0x01]);
        let v = encode_advertisement(&encode_pcp_advertisement(b"WXYZ", &info, mac));
        assert_eq!(parse_advertisement(&v), Some(("WXYZ".into(), info, mac)));
        let header = STANDARD_NO_PAD.encode(encode_advertisement_header(&v));
        assert!(decode_advertisement_header(header.as_bytes()).is_some());
    }

    #[test]
    fn decodes_android_base64_header() {
        // Captured from an Android phone in "everyone" receive mode.
        let h = decode_advertisement_header(b"VSAAABCCIABDAALvZEbPAAA").unwrap();
        assert_eq!(h[0] & 0x0f, 5);
        // A fast advertisement is not a header.
        assert!(decode_advertisement_header(&[0x4a; 27]).is_none());
    }

    #[test]
    fn parses_advertisement() {
        let info = encode_endpoint_info(DeviceType::Phone, "Phone");
        let mac = [0x02, 0, 0, 0, 0, 0x02];
        let mut pcp = vec![0x23];
        pcp.extend_from_slice(&SERVICE_ID_HASH);
        pcp.extend_from_slice(b"WXYZ");
        pcp.push(info.len() as u8);
        pcp.extend_from_slice(&info);
        pcp.extend_from_slice(&mac);
        pcp.extend_from_slice(&[0, 0]);
        let mut v = vec![(2 << 5) | (2 << 2)];
        v.extend_from_slice(&SERVICE_ID_HASH);
        v.extend_from_slice(&(pcp.len() as u32).to_be_bytes());
        v.extend_from_slice(&pcp);
        v.extend_from_slice(&[1, 2]);
        let (id, i, a) = parse_advertisement(&v).unwrap();
        assert_eq!((id.as_str(), i, a), ("WXYZ", info, Address(mac)));
        v[0] |= 0x02; // fast advertisement
        assert!(parse_advertisement(&v).is_none());
    }
}
