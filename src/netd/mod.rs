//! nearcast-netd: the privileged half of the Wi-Fi Direct medium.
//!
//! nearcastd runs as the user, but hosting or joining a Wi-Fi Direct group
//! needs a new wireless interface, a wpa_supplicant to run the group on it,
//! an address and (when hosting) a DHCP server. This system D-Bus service
//! does those on request, for one group at a time, and takes it all down
//! when the caller releases it or leaves the bus.
//!
//! Two backends run the group (`Backend`). Where the system wpa_supplicant
//! manages the station interface (NetworkManager, `wpa_supplicant.service`),
//! netd asks it over D-Bus (`system`), so no second wpa_supplicant runs and
//! nothing is taken over. Otherwise (iwd, or when told to) the group runs on
//! its own interface, nc0, under a private wpa_supplicant. A wiphy has a
//! single P2P device, so the private backend deletes one that iwd or another
//! wpa_supplicant created; they get it back when they restart.

pub mod dhcp;
pub mod nl;
pub mod service;
pub mod system;
pub mod wpa;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use wl_nl80211::Nl80211InterfaceType;

use nl::{Nl, WiphyInfo};

pub const BUS_NAME: &str = "org.nearcast.Netd1";
pub const OBJECT_PATH: &str = "/org/nearcast/Netd1";
pub const POLKIT_ACTION: &str = "org.nearcast.netd.wifi-direct";

/// The group interface the private backend creates.
pub const GROUP_IFACE: &str = "nc0";
/// Our address when we own the group, the one Android uses for its groups.
pub const GO_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 49, 1);
/// The P2P social channels (6, 1, 11), tried in this order when the group
/// can't share the main interface's channel. Every regulatory domain allows
/// them, and peers look there first.
const SOCIAL_FREQS: [u32; 3] = [2437, 2412, 2462];
/// How long wpa_supplicant may take to create its control socket.
const WPA_START_TIMEOUT: Duration = Duration::from_secs(5);
const GROUP_START_TIMEOUT: Duration = Duration::from_secs(15);
const JOIN_TIMEOUT: Duration = Duration::from_secs(25);
const DHCP_TIMEOUT: Duration = Duration::from_secs(20);

fn p2p_ctrl() -> String {
    format!("p2p-dev-{GROUP_IFACE}")
}

/// A group we own.
#[derive(Debug, Clone)]
pub struct HostedGroup {
    pub ssid: String,
    pub passphrase: String,
    pub freq: u32,
    pub gateway: Ipv4Addr,
}

/// A group we joined.
#[derive(Debug, Clone)]
pub struct JoinedGroup {
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

/// Which wpa_supplicant runs the groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Backend {
    /// The system wpa_supplicant when it manages the station interface,
    /// otherwise a private one.
    #[default]
    Auto,
    /// Always the system wpa_supplicant, over D-Bus; fail if it doesn't
    /// manage the station interface.
    System,
    /// Always a private wpa_supplicant on nc0.
    Private,
}

/// A running group, its address and (when hosting) the DHCP server.
pub struct Group {
    /// The group's network interface.
    iface: String,
    dhcp: Option<JoinHandle<()>>,
    kind: Kind,
}

enum Kind {
    Private(Private),
    System(system::SysGroup),
}

/// A private wpa_supplicant on nc0.
struct Private {
    dir: PathBuf,
    child: Child,
    ctrl: wpa::Ctrl,
    events: wpa::Events,
}

/// The station interface and the wiphy it's on.
struct Station {
    name: Option<String>,
    freq: Option<u32>,
    wiphy: u32,
}

async fn station(nl: &Nl) -> anyhow::Result<Station> {
    let ifaces = nl.interfaces().await?;
    let st = ifaces.iter().find(|i| i.kind == Nl80211InterfaceType::Station);
    let wiphy = st.or(ifaces.first()).map(|i| i.wiphy).context("no wireless device")?;
    Ok(Station { name: st.and_then(|i| i.name.clone()), freq: st.and_then(|i| i.freq), wiphy })
}

/// The system wpa_supplicant to use, or None for a private one.
async fn system_backend(backend: Backend, station: &Station) -> anyhow::Result<Option<system::System>> {
    if backend == Backend::Private {
        return Ok(None);
    }
    let found = match &station.name {
        Some(name) => system::find(name).await,
        None => Ok(None),
    };
    match (backend, found) {
        (Backend::System, Ok(Some(s))) => Ok(Some(s)),
        (Backend::System, Ok(None)) => bail!("the system wpa_supplicant doesn't manage {:?}", station.name),
        (Backend::System, Err(e)) => Err(e),
        (_, Ok(found)) => {
            if found.is_none() {
                tracing::debug!("system wpa_supplicant doesn't manage {:?}; using a private one", station.name);
            }
            Ok(found)
        }
        (_, Err(e)) => {
            tracing::warn!("system wpa_supplicant unusable, using a private one: {e:#}");
            Ok(None)
        }
    }
}

impl Group {
    /// Starts a group with us as the owner, on the first channel from
    /// `group_freqs` that wpa_supplicant accepts.
    pub async fn host(nl: &Nl, dir: &Path, backend: Backend) -> anyhow::Result<(Self, HostedGroup)> {
        let st = station(nl).await?;
        let info = nl.wiphy(st.wiphy).await?;
        let freqs = group_freqs(st.freq, &info);
        tracing::info!(
            "group channels to try {freqs:?} (station on {:?}, {} channel(s) at once)",
            st.freq,
            info.go_channels
        );
        let (kind, iface, ssid, passphrase, freq) = match system_backend(backend, &st).await? {
            Some(sys) => {
                let mut last = None;
                let mut started = None;
                for &f in &freqs {
                    match sys.host(f, GROUP_START_TIMEOUT).await {
                        Ok(g) => {
                            started = Some(g);
                            break;
                        }
                        Err(e) => {
                            tracing::info!("no group on {f} MHz: {e:#}");
                            last = Some(e);
                        }
                    }
                }
                let (g, ssid, pass, freq) = match started {
                    Some(g) => g,
                    None => return Err(last.unwrap_or_else(|| anyhow::anyhow!("no channel to try"))),
                };
                let iface = g.ifname.clone();
                (Kind::System(g), iface, ssid, pass, freq)
            }
            None => {
                let mut p = Private::start(nl, dir, st.wiphy).await?;
                let mut result = Err(anyhow::anyhow!("no channel to try"));
                for &f in &freqs {
                    result = p.host(f).await;
                    match &result {
                        Ok(_) => break,
                        Err(e) => tracing::info!("no group on {f} MHz: {e:#}"),
                    }
                }
                match result {
                    Ok((ssid, pass, freq)) => (Kind::Private(p), GROUP_IFACE.to_owned(), ssid, pass, freq),
                    Err(e) => {
                        p.stop().await;
                        return Err(e);
                    }
                }
            }
        };
        let mut group = Group { iface, dhcp: None, kind };
        if let Err(e) = add_address(&group.iface, GO_ADDRESS, 24).await {
            group.stop().await;
            return Err(e);
        }
        let iface = group.iface.clone();
        group.dhcp = Some(tokio::spawn(async move {
            if let Err(e) = dhcp::serve(&iface, GO_ADDRESS).await {
                tracing::warn!("DHCP server stopped: {e:#}");
            }
        }));
        tracing::info!("hosting {ssid:?} on {freq} MHz ({})", group.iface);
        Ok((group, HostedGroup { ssid, passphrase, freq, gateway: GO_ADDRESS }))
    }

    /// Joins another device's group as a client.
    pub async fn join(
        nl: &Nl,
        dir: &Path,
        backend: Backend,
        ssid: &str,
        passphrase: &str,
        freq: u32,
    ) -> anyhow::Result<(Self, JoinedGroup)> {
        if !(8..=63).contains(&passphrase.len()) || passphrase.contains(['"', '\n']) {
            bail!("unusable passphrase");
        }
        let st = station(nl).await?;
        let (kind, iface) = match system_backend(backend, &st).await? {
            Some(sys) => {
                let g = sys.join(ssid, passphrase, freq, JOIN_TIMEOUT).await?;
                let iface = g.ifname.clone();
                (Kind::System(g), iface)
            }
            None => {
                let mut p = Private::start(nl, dir, st.wiphy).await?;
                if let Err(e) = p.join(ssid, passphrase, freq).await {
                    p.stop().await;
                    return Err(e);
                }
                (Kind::Private(p), GROUP_IFACE.to_owned())
            }
        };
        let mut group = Group { iface, dhcp: None, kind };
        match group.get_address(nl).await {
            Ok(j) => {
                tracing::info!("joined {ssid:?} as {} ({})", j.address, group.iface);
                Ok((group, j))
            }
            Err(e) => {
                group.stop().await;
                Err(e)
            }
        }
    }

    async fn get_address(&mut self, nl: &Nl) -> anyhow::Result<JoinedGroup> {
        let mac = nl
            .interfaces()
            .await?
            .into_iter()
            .find(|i| i.name.as_deref() == Some(self.iface.as_str()))
            .and_then(|i| i.mac)
            .context("no group interface address")?;
        let lease = tokio::time::timeout(DHCP_TIMEOUT, dhcp::request(&self.iface, mac))
            .await
            .context("timed out getting an address")??;
        add_address(&self.iface, lease.address, lease.prefix).await?;
        Ok(JoinedGroup { address: lease.address, gateway: lease.router.unwrap_or(lease.server) })
    }

    /// Takes the group down.
    pub async fn stop(mut self) {
        if let Some(d) = self.dhcp.take() {
            d.abort();
        }
        match self.kind {
            Kind::Private(p) => p.stop().await,
            Kind::System(g) => g.stop().await,
        }
    }
}

impl Private {
    async fn start(nl: &Nl, dir: &Path, wiphy: u32) -> anyhow::Result<Self> {
        let ifaces = nl.interfaces().await?;
        // A leftover from a run that didn't clean up.
        for i in ifaces.iter().filter(|i| i.name.as_deref() == Some(GROUP_IFACE)) {
            nl.delete(i.wdev).await.context("removing an old group interface")?;
        }
        for i in ifaces.iter().filter(|i| i.wiphy == wiphy && i.kind == Nl80211InterfaceType::P2pDevice) {
            tracing::info!("taking over the P2P device (wdev {:#x})", i.wdev);
            nl.delete(i.wdev).await.context("removing the existing P2P device")?;
        }
        nl.add(wiphy, GROUP_IFACE, Nl80211InterfaceType::Ap)
            .await
            .context("adding the group interface")?;

        let conf = dir.join("p2p.conf");
        std::fs::write(
            &conf,
            format!(
                "ctrl_interface={}\ndevice_name=nearcast\np2p_no_group_iface=1\np2p_go_ht40=1\np2p_go_vht=1\nupdate_config=0\n",
                dir.display()
            ),
        )?;
        let child = Command::new("wpa_supplicant")
            .args(["-i", GROUP_IFACE, "-D", "nl80211", "-c"])
            .arg(&conf)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("starting wpa_supplicant")?;
        let mut p = Self {
            dir: dir.to_owned(),
            child,
            ctrl: wpa::Ctrl::connect_when_ready(dir, &p2p_ctrl(), WPA_START_TIMEOUT).await?,
            events: wpa::Ctrl::connect(dir, &p2p_ctrl())?.attach().await?,
        };
        if let Ok(Some(status)) = p.child.try_wait() {
            bail!("wpa_supplicant exited: {status}");
        }
        Ok(p)
    }

    async fn host(&mut self, freq: u32) -> anyhow::Result<(String, String, u32)> {
        self.ctrl.ok(&format!("P2P_GROUP_ADD freq={freq}")).await?;
        let f = self.group_started(GROUP_START_TIMEOUT).await?;
        if f.get("2").map(String::as_str) != Some("GO") {
            bail!("expected to own the group");
        }
        Ok((
            f.get("ssid").cloned().context("no SSID")?,
            f.get("passphrase").cloned().context("no passphrase")?,
            f.get("freq").and_then(|v| v.parse().ok()).unwrap_or(freq),
        ))
    }

    async fn join(&mut self, ssid: &str, passphrase: &str, freq: u32) -> anyhow::Result<()> {
        // A persistent group in client mode: wpa_supplicant joins it as a
        // P2P client with the credentials alone, as Android does for
        // WifiP2pConfig with a network name and passphrase.
        let id: u32 = self.ctrl.request("ADD_NETWORK").await?.parse().context("ADD_NETWORK")?;
        let hex: String = ssid.bytes().map(|b| format!("{b:02x}")).collect();
        for set in [
            format!("ssid {hex}"),
            format!("psk \"{passphrase}\""),
            "mode 0".into(),
            "disabled 2".into(),
        ] {
            self.ctrl.ok(&format!("SET_NETWORK {id} {set}")).await?;
        }
        let freq_arg = if freq > 0 { format!(" freq={freq}") } else { String::new() };
        self.ctrl.ok(&format!("P2P_GROUP_ADD persistent={id}{freq_arg}")).await?;
        let f = self.group_started(JOIN_TIMEOUT).await?;
        if f.get("2").map(String::as_str) != Some("client") {
            bail!("expected to join as a client");
        }
        Ok(())
    }

    async fn group_started(&self, timeout: Duration) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let ev = tokio::time::timeout(
            timeout,
            self.events.wait_for(&[
                "P2P-GROUP-STARTED",
                "P2P-GROUP-FORMATION-FAILURE",
                "P2P-GROUP-REMOVED",
            ]),
        )
        .await
        .context("timed out starting the group")??;
        let f = wpa::fields(&ev);
        if f.get("0").map(String::as_str) != Some("P2P-GROUP-STARTED") {
            bail!("group didn't start: {ev}");
        }
        Ok(f)
    }

    /// Takes the group down and removes the interface. wpa_supplicant
    /// removes the P2P device it created as it exits.
    async fn stop(mut self) {
        let _ = self.ctrl.request(&format!("P2P_GROUP_REMOVE {GROUP_IFACE}")).await;
        let _ = self.ctrl.request("TERMINATE").await;
        if tokio::time::timeout(Duration::from_secs(3), self.child.wait()).await.is_err() {
            tracing::warn!("wpa_supplicant didn't exit; killing it");
            let _ = self.child.kill().await;
        }
        let _ = std::fs::remove_file(self.dir.join("p2p.conf"));
        if let Ok(nl) = Nl::new()
            && let Ok(ifaces) = nl.interfaces().await
        {
            for i in ifaces.iter().filter(|i| i.name.as_deref() == Some(GROUP_IFACE)) {
                let _ = nl.delete(i.wdev).await;
            }
        }
        tracing::info!("group stopped");
    }
}

/// The channels to try for the group, best first. The station's channel
/// comes first when the regulatory domain lets us start a group there,
/// either outright or because it's IR-concurrent and the station is
/// connected on it (the kernel's rule for a group owner beside a station),
/// since the radio then stays on one channel. Then a usable social channel,
/// any usable 2.4 GHz channel, any usable channel. wpa_supplicant may still
/// refuse an IR-concurrent channel, so the caller tries the next one. When
/// the wiphy can't use a second channel next to the station, the station
/// drops for the group's lifetime; that's logged.
fn group_freqs(station: Option<u32>, info: &WiphyInfo) -> Vec<u32> {
    let chan = |f: u32| info.channels.iter().find(|c| c.freq == f);
    let usable = |f: u32| chan(f).is_some_and(|c| c.usable);
    let mut out = Vec::new();
    if let Some(s) = station.filter(|&s| chan(s).is_some_and(|c| c.usable || c.ir_concurrent)) {
        out.push(s);
    }
    let fallback = SOCIAL_FREQS
        .into_iter()
        .find(|&f| usable(f))
        .or_else(|| info.channels.iter().find(|c| c.usable && c.freq < 2500).map(|c| c.freq))
        .or_else(|| info.channels.iter().find(|c| c.usable).map(|c| c.freq))
        .unwrap_or(SOCIAL_FREQS[0]);
    if !out.contains(&fallback) {
        out.push(fallback);
    }
    // The fallback only shares the station's channel if it is that channel.
    if station.is_some_and(|s| out.first() != Some(&s)) && info.go_channels < 2 {
        tracing::warn!("the station's channel can't host a group and the radio can't use two channels");
    }
    out
}

async fn add_address(iface: &str, addr: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    let index = nix::net::if_::if_nametoindex(iface).with_context(|| format!("no interface {iface}"))?;
    let (conn, handle, _) = rtnetlink::new_connection()?;
    let conn = tokio::spawn(conn);
    let r = handle.address().add(index, IpAddr::V4(addr), prefix).execute().await;
    conn.abort();
    r.with_context(|| format!("adding {addr}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::group_freqs;
    use super::nl::{Channel, WiphyInfo};

    /// (freq, usable, ir_concurrent)
    fn info(chans: &[(u32, bool, bool)], go_channels: u32) -> WiphyInfo {
        WiphyInfo {
            channels: chans
                .iter()
                .map(|&(freq, usable, ir_concurrent)| Channel { freq, usable, ir_concurrent })
                .collect(),
            go_channels,
        }
    }

    #[test]
    fn group_channel_choice() {
        // World domain: 2.4 GHz usable, 5 GHz no-IR.
        let world = info(&[(2412, true, false), (2437, true, false), (2462, true, false), (2472, false, false), (5180, false, false)], 2);
        assert_eq!(group_freqs(Some(2412), &world), [2412, 2437]);
        assert_eq!(group_freqs(Some(2437), &world), [2437]);
        assert_eq!(group_freqs(Some(5180), &world), [2437]);
        assert_eq!(group_freqs(None, &world), [2437]);
        // Intel LAR: 5 GHz no-IR but IR-concurrent. Try the station's
        // channel, then 2.4 GHz.
        let lar = info(&[(2412, true, false), (2437, true, false), (5180, false, true), (5260, false, false)], 2);
        assert_eq!(group_freqs(Some(5180), &lar), [5180, 2437]);
        assert_eq!(group_freqs(Some(5260), &lar), [2437]);
        // A country that allows 5 GHz: stay on the station's channel.
        let country = info(&[(2412, true, false), (2437, true, false), (5180, true, false)], 1);
        assert_eq!(group_freqs(Some(5180), &country), [5180, 2437]);
        // No social channel usable.
        let odd = info(&[(2417, true, false), (5745, true, false)], 2);
        assert_eq!(group_freqs(None, &odd), [2417]);
    }
}
