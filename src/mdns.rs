//! Discovery and advertising on the local network (mDNS / DNS-SD).
//!
//! Quick Share devices register `_FC9F5ED42C8A._tcp` with an instance name
//! encoding the endpoint ID and a TXT record `n` holding the endpoint info.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::endpoint::{
    decode_endpoint_info, mdns_instance_name, parse_mdns_instance_name, DeviceType, MDNS_SERVICE_TYPE,
};

pub struct Mdns {
    daemon: ServiceDaemon,
    registered: Option<String>,
}

/// A Quick Share device found on the network.
#[derive(Debug, Clone)]
pub struct Found {
    pub fullname: String,
    pub endpoint_id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub addr: SocketAddr,
}

pub enum Change {
    Found(Found),
    Lost { fullname: String },
}

impl Mdns {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self { daemon: ServiceDaemon::new().context("starting mDNS")?, registered: None })
    }

    /// Makes this device visible to others on the network.
    pub fn advertise(&mut self, endpoint_id: &[u8; 4], endpoint_info: &[u8], port: u16) -> anyhow::Result<()> {
        self.withdraw();
        let host = hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "nearcast".into());
        let info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &mdns_instance_name(endpoint_id),
            &format!("{host}.local."),
            "",
            port,
            &[("n", URL_SAFE_NO_PAD.encode(endpoint_info))][..],
        )?
        .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        self.daemon.register(info)?;
        self.registered = Some(fullname);
        Ok(())
    }

    /// Stops advertising. mdns-sd sends the goodbye packets from its own
    /// thread, in order with later commands, so this doesn't wait for them.
    pub fn withdraw(&mut self) {
        if let Some(name) = self.registered.take() {
            let _ = self.daemon.unregister(&name);
        }
    }

    /// Starts browsing; changes arrive on the returned channel until [`Self::stop_browse`].
    pub fn browse(&self, own_id: [u8; 4]) -> anyhow::Result<tokio::sync::mpsc::UnboundedReceiver<Change>> {
        let rx = self.daemon.browse(MDNS_SERVICE_TYPE)?;
        let (tx, out) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(ev) = rx.recv_async().await {
                let change = match ev {
                    ServiceEvent::ServiceResolved(s) => match parse_resolved(&s, &own_id) {
                        Some(f) => Change::Found(f),
                        None => continue,
                    },
                    ServiceEvent::ServiceRemoved(_, fullname) => Change::Lost { fullname },
                    ServiceEvent::SearchStopped(_) => break,
                    _ => continue,
                };
                if tx.send(change).is_err() {
                    break;
                }
            }
        });
        Ok(out)
    }

    pub fn stop_browse(&self) {
        let _ = self.daemon.stop_browse(MDNS_SERVICE_TYPE);
    }

    /// Withdraws and stops the mDNS thread, waiting up to a second for it
    /// so the goodbye packets go out before the process exits.
    pub async fn shutdown(mut self) {
        self.withdraw();
        if let Ok(rx) = self.daemon.shutdown() {
            let _ = tokio::time::timeout(Duration::from_secs(1), rx.recv_async()).await;
        }
    }
}

fn parse_resolved(s: &ResolvedService, own_id: &[u8; 4]) -> Option<Found> {
    let instance = s.get_fullname().strip_suffix(&format!(".{MDNS_SERVICE_TYPE}"))?;
    let id = parse_mdns_instance_name(instance)?;
    if &id == own_id {
        return None;
    }
    let info = URL_SAFE_NO_PAD.decode(s.get_property_val_str("n")?).ok()?;
    let (device_type, name) = decode_endpoint_info(&info).ok()?;
    // Prefer a routable address over link-local.
    let mut addrs: Vec<_> = s.get_addresses_v4().into_iter().collect();
    addrs.sort_by_key(|a| (a.is_link_local(), *a));
    let ip = *addrs.first()?;
    Some(Found {
        fullname: s.get_fullname().to_owned(),
        endpoint_id: String::from_utf8_lossy(&id).into_owned(),
        name: name.unwrap_or_else(|| "Unknown device".into()),
        device_type,
        addr: SocketAddr::new(IpAddr::V4(ip), s.get_port()),
    })
}
