//! The org.nearcast.Netd1 D-Bus interface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use zbus::fdo;
use zbus::message::Header;
use zbus::zvariant::Value;

use super::nl::Nl;
use super::{Backend, Group, POLKIT_ACTION};

struct Session {
    id: u32,
    owner: String,
    group: Group,
}

#[derive(Default)]
struct State {
    next_id: u32,
    session: Option<Session>,
}

#[derive(Clone)]
pub struct Netd {
    dir: PathBuf,
    backend: Backend,
    nl: Arc<Nl>,
    state: Arc<Mutex<State>>,
}

impl Netd {
    pub fn new(dir: PathBuf, backend: Backend) -> anyhow::Result<Self> {
        Ok(Self { dir, backend, nl: Arc::new(Nl::new()?), state: Arc::default() })
    }

    /// Takes down whatever group is up.
    pub async fn shutdown(&self) {
        if let Some(s) = self.state.lock().await.session.take() {
            s.group.stop().await;
        }
    }

    async fn release_id(&self, id: u32) -> bool {
        let mut st = self.state.lock().await;
        if st.session.as_ref().is_some_and(|s| s.id == id) {
            let s = st.session.take().unwrap();
            drop(st);
            s.group.stop().await;
            true
        } else {
            false
        }
    }

    /// Checks the caller may use the action, then claims the single session
    /// slot for it while `start` runs.
    async fn begin(
        &self,
        hdr: &Header<'_>,
        conn: &zbus::Connection,
    ) -> fdo::Result<(String, tokio::sync::OwnedMutexGuard<State>)> {
        let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?.to_string();
        authorize(conn, &sender).await?;
        let st = self.state.clone().lock_owned().await;
        if st.session.is_some() {
            return Err(fdo::Error::LimitsExceeded("a Wi-Fi Direct group is already up".into()));
        }
        Ok((sender, st))
    }

    fn finish(&self, conn: &zbus::Connection, st: &mut State, owner: String, group: Group) -> u32 {
        st.next_id = st.next_id.wrapping_add(1).max(1);
        let id = st.next_id;
        st.session = Some(Session { id, owner: owner.clone(), group });
        // Take the group down if its owner leaves the bus without releasing it.
        let this = self.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            let Ok(dbus) = fdo::DBusProxy::new(&conn).await else { return };
            let Ok(mut changes) = dbus.receive_name_owner_changed_with_args(&[(0, owner.as_str())]).await else {
                return;
            };
            // It may have left before we subscribed.
            let gone = match owner.as_str().try_into() {
                Ok(name) => !dbus.name_has_owner(name).await.unwrap_or(false),
                Err(_) => true,
            };
            if gone {
                this.release_id(id).await;
                return;
            }
            while let Some(sig) = changes.next().await {
                if sig.args().is_ok_and(|a| a.new_owner().is_none()) {
                    if this.release_id(id).await {
                        tracing::info!("{owner} left the bus; released its group");
                    }
                    return;
                }
                if this.state.lock().await.session.as_ref().is_none_or(|s| s.id != id) {
                    return;
                }
            }
        });
        id
    }
}

fn failed(e: anyhow::Error) -> fdo::Error {
    tracing::warn!("{e:#}");
    fdo::Error::Failed(format!("{e:#}"))
}

#[zbus::interface(name = "org.nearcast.Netd1")]
impl Netd {
    /// What this service can do.
    fn capabilities(&self) -> Vec<String> {
        vec!["wifi-direct-host".into(), "wifi-direct-join".into()]
    }

    /// Starts a Wi-Fi Direct group with this device as its owner. Returns a
    /// session ID for Release, the group's SSID, passphrase, frequency in
    /// MHz and our address on it.
    async fn host_wifi_direct(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<(u32, String, String, u32, String)> {
        let (owner, mut st) = self.begin(&hdr, conn).await?;
        tracing::info!("{owner} asked to host a group");
        let (group, h) = Group::host(&self.nl, &self.dir, self.backend).await.map_err(failed)?;
        let id = self.finish(conn, &mut st, owner, group);
        Ok((id, h.ssid, h.passphrase, h.freq, h.gateway.to_string()))
    }

    /// Joins another device's Wi-Fi Direct group with its credentials.
    /// Returns a session ID for Release, our address and the group owner's.
    async fn join_wifi_direct(
        &self,
        ssid: String,
        passphrase: String,
        freq: u32,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<(u32, String, String)> {
        let (owner, mut st) = self.begin(&hdr, conn).await?;
        tracing::info!("{owner} asked to join {ssid:?} on {freq} MHz");
        let (group, j) = Group::join(&self.nl, &self.dir, self.backend, &ssid, &passphrase, freq).await.map_err(failed)?;
        let id = self.finish(conn, &mut st, owner, group);
        Ok((id, j.address.to_string(), j.gateway.to_string()))
    }

    /// Takes down the group from HostWifiDirect or JoinWifiDirect.
    async fn release(&self, id: u32, #[zbus(header)] hdr: Header<'_>) -> fdo::Result<()> {
        let sender = hdr.sender().map(|s| s.to_string());
        let owned = self.state.lock().await.session.as_ref().is_some_and(|s| s.id == id && Some(&s.owner) == sender.as_ref());
        if !owned {
            return Err(fdo::Error::AccessDenied("not your group".into()));
        }
        self.release_id(id).await;
        Ok(())
    }
}

/// Asks polkit whether `sender` may use netd, without prompting: the policy
/// allows active local sessions.
async fn authorize(conn: &zbus::Connection, sender: &str) -> fdo::Result<()> {
    let subject: (&str, HashMap<&str, Value<'_>>) =
        ("system-bus-name", HashMap::from([("name", Value::from(sender))]));
    let details: HashMap<&str, &str> = HashMap::new();
    let reply = conn
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, POLKIT_ACTION, details, 0u32, ""),
        )
        .await
        .map_err(|e| fdo::Error::AccessDenied(format!("polkit: {e}")))?;
    let (authorized, _, _): (bool, bool, HashMap<String, String>) =
        reply.body().deserialize().map_err(|e| fdo::Error::AccessDenied(format!("polkit: {e}")))?;
    if authorized {
        Ok(())
    } else {
        Err(fdo::Error::AccessDenied("not authorized".into()))
    }
}
