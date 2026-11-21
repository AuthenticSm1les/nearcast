//! The system wpa_supplicant as netd's backend, over its D-Bus API
//! (`fi.w1.wpa_supplicant1`), for hosts where it already manages the
//! station interface (NetworkManager, `wpa_supplicant.service`). Groups then
//! run under that instance: netd starts no wpa_supplicant of its own and
//! leaves the P2P device alone.
//!
//! The P2P methods act on the interface's P2P manager (its P2P device, where
//! the driver has one), so they're called on the station's interface object.
//! Hosting is GroupAdd with a frequency. Joining adds a persistent group in
//! client mode with the peer's SSID and passphrase and starts it with
//! GroupAdd, as netd's private backend does over the control socket.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context};
use futures_util::StreamExt;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

const SERVICE: &str = "fi.w1.wpa_supplicant1";
const ROOT_PATH: &str = "/fi/w1/wpa_supplicant1";
const IFACE: &str = "fi.w1.wpa_supplicant1.Interface";
const P2P: &str = "fi.w1.wpa_supplicant1.Interface.P2PDevice";
const GROUP: &str = "fi.w1.wpa_supplicant1.Group";

/// The system wpa_supplicant's object for the station interface.
pub struct System {
    conn: Connection,
    iface: OwnedObjectPath,
}

/// A group running under the system wpa_supplicant.
pub struct SysGroup {
    conn: Connection,
    /// The station interface's object, for RemovePersistentGroup.
    iface: OwnedObjectPath,
    /// The group interface's object, for Disconnect.
    group_iface: OwnedObjectPath,
    group: OwnedObjectPath,
    persistent: Option<OwnedObjectPath>,
    pub ifname: String,
    pub role: String,
}

/// Finds the system wpa_supplicant's interface object for `station`, if
/// wpa_supplicant is on the bus and manages that interface.
pub async fn find(station: &str) -> anyhow::Result<Option<System>> {
    let conn = Connection::system().await?;
    let dbus = zbus::fdo::DBusProxy::new(&conn).await?;
    if !dbus.name_has_owner(SERVICE.try_into()?).await? {
        return Ok(None);
    }
    let reply = conn
        .call_method(Some(SERVICE), ROOT_PATH, Some(SERVICE), "GetInterface", &(station,))
        .await;
    let iface: OwnedObjectPath = match reply {
        Ok(r) => r.body().deserialize()?,
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == "fi.w1.wpa_supplicant1.InterfaceUnknown" => {
            return Ok(None);
        }
        Err(e) => return Err(e).context("asking wpa_supplicant for the station interface"),
    };
    Ok(Some(System { conn, iface }))
}

impl System {
    /// Starts a group with us as the owner on `freq`.
    pub async fn host(&self, freq: u32, timeout: Duration) -> anyhow::Result<(SysGroup, String, String, u32)> {
        let args = HashMap::from([("frequency", Value::from(freq as i32)), ("ht40", Value::from(true))]);
        let g = self.start(args, None, timeout).await?;
        let checked = async {
            if g.role != "GO" {
                bail!("expected to own the group, got role {:?}", g.role);
            }
            let ssid: Vec<u8> = self.prop(&g.group, GROUP, "SSID").await?;
            let passphrase: String = self.prop(&g.group, GROUP, "Passphrase").await?;
            let freq = self.prop::<u16>(&g.group, GROUP, "Frequency").await.map(u32::from).unwrap_or(freq);
            anyhow::Ok((String::from_utf8(ssid).context("non-UTF-8 SSID")?, passphrase, freq))
        };
        match checked.await {
            Ok((ssid, passphrase, freq)) => Ok((g, ssid, passphrase, freq)),
            Err(e) => {
                g.stop().await;
                Err(e)
            }
        }
    }

    /// Joins another device's group as a client with its credentials.
    pub async fn join(&self, ssid: &str, passphrase: &str, freq: u32, timeout: Duration) -> anyhow::Result<SysGroup> {
        let net = HashMap::from([
            // A byte array is written as hex, so any SSID works; strings
            // other than a few keys are quoted by wpa_supplicant.
            ("ssid", Value::from(ssid.as_bytes().to_vec())),
            ("psk", Value::from(passphrase)),
        ]);
        let reply = self
            .conn
            .call_method(Some(SERVICE), &self.iface, Some(P2P), "AddPersistentGroup", &(net,))
            .await
            .context("adding the group's credentials")?;
        let persistent: OwnedObjectPath = reply.body().deserialize()?;
        let mut args = HashMap::from([("persistent_group_object", Value::from(ObjectPath::from(&persistent)))]);
        if freq > 0 {
            args.insert("frequency", Value::from(freq as i32));
        }
        let g = match self.start(args, Some(persistent.clone()), timeout).await {
            Ok(g) => g,
            Err(e) => {
                self.remove_persistent(&persistent).await;
                return Err(e);
            }
        };
        if g.role != "client" {
            let role = g.role.clone();
            g.stop().await;
            bail!("expected to join as a client, got role {role:?}");
        }
        Ok(g)
    }

    /// Calls GroupAdd and waits for GroupStarted.
    async fn start(
        &self,
        args: HashMap<&str, Value<'_>>,
        persistent: Option<OwnedObjectPath>,
        timeout: Duration,
    ) -> anyhow::Result<SysGroup> {
        // Subscribe before asking, so the signal can't be missed.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(SERVICE)?
            .interface(P2P)?
            .member("GroupStarted")?
            .build();
        let mut started = zbus::MessageStream::for_match_rule(rule, &self.conn, Some(8)).await?;
        self.conn
            .call_method(Some(SERVICE), &self.iface, Some(P2P), "GroupAdd", &(args,))
            .await
            .context("asking wpa_supplicant for a group")?;
        let msg = tokio::time::timeout(timeout, started.next())
            .await
            .context("timed out starting the group")?
            .context("wpa_supplicant left the bus")??;
        let mut f: HashMap<String, OwnedValue> = msg.body().deserialize()?;
        let mut take = |k: &str| f.remove(k).with_context(|| format!("GroupStarted without {k}"));
        let group_iface = OwnedObjectPath::try_from(take("interface_object")?)?;
        let group = OwnedObjectPath::try_from(take("group_object")?)?;
        let role = String::try_from(take("role")?)?;
        let ifname: String = self.prop(&group_iface, IFACE, "Ifname").await?;
        tracing::info!("system wpa_supplicant started a group on {ifname} as {role}");
        Ok(SysGroup { conn: self.conn.clone(), iface: self.iface.clone(), group_iface, group, persistent, ifname, role })
    }

    async fn prop<T>(&self, path: &OwnedObjectPath, iface: &str, name: &str) -> anyhow::Result<T>
    where
        T: TryFrom<OwnedValue>,
        T::Error: Into<zbus::zvariant::Error>,
    {
        prop(&self.conn, path, iface, name).await
    }

    async fn remove_persistent(&self, path: &OwnedObjectPath) {
        remove_persistent(&self.conn, &self.iface, path).await
    }
}

impl SysGroup {
    /// Leaves or takes down the group and forgets the credentials it used.
    pub async fn stop(self) {
        if let Err(e) = self.conn.call_method(Some(SERVICE), &self.group_iface, Some(P2P), "Disconnect", &()).await {
            tracing::warn!("taking the group on {} down: {e}", self.ifname);
        }
        if let Some(p) = &self.persistent {
            remove_persistent(&self.conn, &self.iface, p).await;
        }
        tracing::info!("group stopped");
    }
}

async fn prop<T>(conn: &Connection, path: &OwnedObjectPath, iface: &str, name: &str) -> anyhow::Result<T>
where
    T: TryFrom<OwnedValue>,
    T::Error: Into<zbus::zvariant::Error>,
{
    let reply = conn
        .call_method(Some(SERVICE), path, Some("org.freedesktop.DBus.Properties"), "Get", &(iface, name))
        .await
        .with_context(|| format!("reading {name}"))?;
    let v: OwnedValue = reply.body().deserialize()?;
    T::try_from(v).map_err(|e| anyhow::anyhow!("{name}: {}", e.into()))
}

async fn remove_persistent(conn: &Connection, iface: &OwnedObjectPath, path: &OwnedObjectPath) {
    let _ = conn
        .call_method(Some(SERVICE), iface, Some(P2P), "RemovePersistentGroup", &(ObjectPath::from(path),))
        .await;
}
