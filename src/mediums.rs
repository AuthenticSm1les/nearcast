//! The mediums nearcastd can upgrade connections to (see [`crate::upgrade`]).
//!
//! WIFI_LAN needs nothing but a local network address: the host listens on a
//! TCP port and the other side connects to it.
//!
//! WIFI_DIRECT asks nearcast-netd (see [`crate::netd`]) on the system bus to
//! start or join a group, then does the same over the group's addresses.
//!
//! WIFI_HOTSPOT is hosted with the same group: a Wi-Fi Direct group owner is
//! an ordinary WPA2 access point to devices that join it as a network, which
//! is what a hotspot client does. Joining someone else's hotspot would need
//! the station interface (on most cards the only one allowed), so we don't
//! offer that.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use tokio::net::{TcpListener, TcpStream};

use crate::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::{
    Medium, WifiDirectCredentials, WifiHotspotCredentials, WifiLanSocket,
};
use crate::proto::connections::bandwidth_upgrade_negotiation_frame::UpgradePathInfo;
use crate::upgrade::{BoxStream, Hosted, Joined, Mediums};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The mediums enabled for this daemon, most preferred first.
pub struct Available {
    enabled: Vec<Medium>,
}

impl Available {
    pub fn new(enabled: Vec<Medium>) -> Self {
        Self { enabled }
    }

    fn usable(&self, m: Medium) -> bool {
        self.enabled.contains(&m)
            && match m {
                Medium::WifiLan => lan_address().is_some(),
                // Whether netd is installed and willing shows when we ask it.
                Medium::WifiDirect | Medium::WifiHotspot => true,
                _ => false,
            }
    }
}

impl Mediums for Available {
    fn hostable(&self) -> Vec<Medium> {
        self.enabled.iter().copied().filter(|m| self.usable(*m)).collect()
    }

    fn joinable(&self) -> Vec<Medium> {
        self.hostable().into_iter().filter(|m| *m != Medium::WifiHotspot).collect()
    }

    fn host(&self, medium: Medium) -> BoxFuture<'_, anyhow::Result<Hosted>> {
        async move {
            match medium {
                Medium::WifiLan => host_lan().await,
                Medium::WifiDirect | Medium::WifiHotspot => host_group(medium).await,
                m => bail!("can't host {m:?}"),
            }
        }
        .boxed()
    }

    fn join(&self, info: &UpgradePathInfo) -> BoxFuture<'_, anyhow::Result<Joined>> {
        let info = info.clone();
        async move {
            match info.medium() {
                Medium::WifiLan => join_lan(info.wifi_lan_socket.unwrap_or_default()).await,
                Medium::WifiDirect => join_wifi_direct(info.wifi_direct_credentials.unwrap_or_default()).await,
                m => bail!("can't join {m:?}"),
            }
        }
        .boxed()
    }
}

/// An IPv4 address on an interface that is up, preferring private ones.
fn lan_address() -> Option<Ipv4Addr> {
    let want = InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING;
    let mut addrs: Vec<Ipv4Addr> = getifaddrs()
        .ok()?
        .filter(|a| a.flags.contains(want) && !a.flags.contains(InterfaceFlags::IFF_LOOPBACK))
        .filter_map(|a| a.address?.as_sockaddr_in().map(|s| s.ip()))
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .collect();
    addrs.sort_by_key(|ip| !ip.is_private());
    addrs.first().copied()
}

async fn host_lan() -> anyhow::Result<Hosted> {
    let ip = lan_address().context("no local network address")?;
    let listener = TcpListener::bind((ip, 0)).await?;
    let port = listener.local_addr()?.port();
    tracing::debug!("hosting a LAN upgrade on {ip}:{port}");
    let info = UpgradePathInfo {
        wifi_lan_socket: Some(WifiLanSocket {
            ip_address: Some(ip.octets().to_vec()),
            wifi_port: Some(port.into()),
        }),
        ..Default::default()
    };
    let incoming = async move {
        let (sock, peer) = listener.accept().await?;
        tracing::debug!("upgrade connection from {peer}");
        sock.set_nodelay(true)?;
        Ok(Box::new(sock) as BoxStream)
    }
    .boxed();
    Ok(Hosted { info, incoming, guard: Box::new(()) })
}

async fn connect(addr: SocketAddr) -> anyhow::Result<TcpStream> {
    let sock = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("timed out connecting")??;
    sock.set_nodelay(true)?;
    Ok(sock)
}

async fn join_lan(s: WifiLanSocket) -> anyhow::Result<Joined> {
    let ip: IpAddr = match s.ip_address().len() {
        4 => <[u8; 4]>::try_from(s.ip_address()).unwrap().into(),
        16 => <[u8; 16]>::try_from(s.ip_address()).unwrap().into(),
        n => bail!("bad address length {n}"),
    };
    let port = u16::try_from(s.wifi_port()).context("bad port")?;
    let sock = connect(SocketAddr::new(ip, port)).await?;
    Ok(Joined { stream: Box::new(sock), guard: Box::new(()) })
}

#[zbus::proxy(
    interface = "org.nearcast.Netd1",
    default_service = "org.nearcast.Netd1",
    default_path = "/org/nearcast/Netd1"
)]
trait Netd {
    fn host_wifi_direct(&self) -> zbus::Result<(u32, String, String, u32, String)>;
    fn join_wifi_direct(&self, ssid: &str, passphrase: &str, freq: u32) -> zbus::Result<(u32, String, String)>;
    fn release(&self, id: u32) -> zbus::Result<()>;
}

async fn netd() -> anyhow::Result<NetdProxy<'static>> {
    let conn = zbus::Connection::system().await.context("connecting to the system bus")?;
    Ok(NetdProxy::new(&conn).await?)
}

/// Releases a netd group when the upgraded connection ends. netd also
/// releases it if we leave the bus.
struct NetdGroup {
    netd: NetdProxy<'static>,
    id: u32,
}

impl Drop for NetdGroup {
    fn drop(&mut self) {
        let (netd, id) = (self.netd.clone(), self.id);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Err(e) = netd.release(id).await {
                    tracing::debug!("releasing the Wi-Fi Direct group: {e}");
                }
            });
        }
    }
}

/// Hosts a Wi-Fi Direct group and describes it as `medium`, Wi-Fi Direct or
/// hotspot.
async fn host_group(medium: Medium) -> anyhow::Result<Hosted> {
    let netd = netd().await?;
    let (id, ssid, password, freq, gateway) =
        netd.host_wifi_direct().await.context("nearcast-netd couldn't start a group")?;
    let group = NetdGroup { netd, id };
    let gateway: Ipv4Addr = gateway.parse().context("bad gateway address from netd")?;
    let listener = TcpListener::bind((gateway, 0)).await?;
    let port = listener.local_addr()?.port();
    tracing::debug!("hosting a {medium:?} upgrade on {ssid:?}, {gateway}:{port}");
    let mut info = UpgradePathInfo::default();
    if medium == Medium::WifiHotspot {
        info.wifi_hotspot_credentials = Some(WifiHotspotCredentials {
            ssid: Some(ssid),
            password: Some(password),
            port: Some(port.into()),
            gateway: Some(gateway.to_string()),
            frequency: Some(freq as i32),
        });
    } else {
        info.wifi_direct_credentials = Some(WifiDirectCredentials {
            ssid: Some(ssid),
            password: Some(password),
            port: Some(port.into()),
            frequency: Some(freq as i32),
            gateway: Some(gateway.to_string()),
        });
    }
    let incoming = async move {
        let (sock, peer) = listener.accept().await?;
        tracing::debug!("upgrade connection from {peer}");
        sock.set_nodelay(true)?;
        Ok(Box::new(sock) as BoxStream)
    }
    .boxed();
    Ok(Hosted { info, incoming, guard: Box::new(group) })
}

async fn join_wifi_direct(c: WifiDirectCredentials) -> anyhow::Result<Joined> {
    let port = u16::try_from(c.port()).context("bad port")?;
    let netd = netd().await?;
    let freq = u32::try_from(c.frequency()).unwrap_or(0);
    let (id, address, gateway) = netd
        .join_wifi_direct(c.ssid(), c.password(), freq)
        .await
        .context("nearcast-netd couldn't join the group")?;
    let group = NetdGroup { netd, id };
    // The credentials name the group owner's address; fall back to the one
    // DHCP gave us.
    let host: Ipv4Addr = c
        .gateway()
        .parse()
        .ok()
        .filter(|a: &Ipv4Addr| !a.is_unspecified())
        .or_else(|| gateway.parse().ok())
        .context("no group owner address")?;
    tracing::debug!("joined the Wi-Fi Direct group as {address}; connecting to {host}:{port}");
    let sock = connect(SocketAddr::from((host, port))).await?;
    Ok(Joined { stream: Box::new(sock), guard: Box::new(group) })
}
