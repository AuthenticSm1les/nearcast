//! A client for wpa_supplicant's control interface: a Unix datagram socket
//! per interface, one request and one reply per datagram, with unsolicited
//! events ("<3>P2P-GROUP-STARTED ...") going to sockets that sent ATTACH.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{bail, Context};
use tokio::net::UnixDatagram;

const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_SOCKET: AtomicU32 = AtomicU32::new(0);

pub struct Ctrl {
    sock: UnixDatagram,
    local: PathBuf,
}

impl Ctrl {
    /// Connects to the socket for `iface` under `dir`. The client socket is
    /// bound in the same directory so wpa_supplicant can reply to it.
    pub fn connect(dir: &Path, iface: &str) -> anyhow::Result<Self> {
        let n = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        let local = dir.join(format!("client-{}-{n}", std::process::id()));
        let _ = std::fs::remove_file(&local);
        let sock = UnixDatagram::bind(&local).context("binding a control socket")?;
        let ctrl = Self { sock, local };
        ctrl.sock
            .connect(dir.join(iface))
            .with_context(|| format!("connecting to wpa_supplicant's {iface} socket"))?;
        Ok(ctrl)
    }

    /// Like [`Ctrl::connect`], for a wpa_supplicant that is still starting:
    /// tries again whenever something is created in `dir` (inotify), until
    /// the control socket answers or `timeout` passes. wpa_supplicant's
    /// sockets are datagram sockets, so one accepts a connect as soon as it
    /// exists.
    pub async fn connect_when_ready(dir: &Path, iface: &str, timeout: Duration) -> anyhow::Result<Self> {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use std::os::fd::{AsFd, AsRawFd, RawFd};
        struct Watch(Inotify);
        impl AsRawFd for Watch {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_fd().as_raw_fd()
            }
        }
        let ino = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).context("inotify")?;
        // Watch before the first try, so a socket created in between is seen.
        ino.add_watch(dir, AddWatchFlags::IN_CREATE).context("watching the control directory")?;
        // SAFETY: `Watch` owns the inotify descriptor and never replaces or
        // closes it, so it stays the same open descriptor while registered.
        let watch = unsafe { tokio::io::unix::AsyncFd::register(Watch(ino)) }
            .map_err(|e| anyhow::anyhow!("registering the inotify watch: {e}"))?;
        let wait = async {
            loop {
                let err = match Self::connect(dir, iface) {
                    Ok(c) => return Ok(c),
                    Err(e) => e,
                };
                let mut ready = watch.readable().await?;
                // Drain; which file appeared doesn't matter.
                let _ = ready.get_inner().0.read_events();
                ready.clear_ready();
                tracing::trace!("retrying wpa_supplicant's socket after: {err:#}");
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(r) => r,
            Err(_) => Self::connect(dir, iface).context("wpa_supplicant didn't create its control socket in time"),
        }
    }

    /// Sends a command and returns its reply. Events that arrive in between
    /// (on an attached socket) are skipped.
    pub async fn request(&self, cmd: &str) -> anyhow::Result<String> {
        self.sock.send(cmd.as_bytes()).await?;
        let mut buf = vec![0u8; 4096];
        tokio::time::timeout(REPLY_TIMEOUT, async {
            loop {
                let n = self.sock.recv(&mut buf).await?;
                if buf.first() != Some(&b'<') {
                    return Ok(String::from_utf8_lossy(&buf[..n]).trim_end().to_owned());
                }
            }
        })
        .await
        .with_context(|| format!("no reply to {}", cmd.split(' ').next().unwrap_or(cmd)))?
    }

    /// Sends a command that answers OK.
    pub async fn ok(&self, cmd: &str) -> anyhow::Result<()> {
        let reply = self.request(cmd).await?;
        if reply != "OK" {
            bail!("{} failed: {reply}", cmd.split(' ').next().unwrap_or(cmd));
        }
        Ok(())
    }

    /// Turns this socket into an event monitor.
    pub async fn attach(self) -> anyhow::Result<Events> {
        self.ok("ATTACH").await?;
        Ok(Events { ctrl: self })
    }
}

impl Drop for Ctrl {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.local);
    }
}

pub struct Events {
    ctrl: Ctrl,
}

impl Events {
    /// The next event, without its "<level>" prefix.
    pub async fn next(&self) -> anyhow::Result<String> {
        let mut buf = vec![0u8; 4096];
        loop {
            let n = self.ctrl.sock.recv(&mut buf).await?;
            let msg = String::from_utf8_lossy(&buf[..n]);
            if let Some(rest) = msg.strip_prefix('<')
                && let Some((_, event)) = rest.split_once('>') {
                    return Ok(event.trim_end().to_owned());
                }
        }
    }

    /// Waits for an event starting with one of `names`, returning it.
    pub async fn wait_for(&self, names: &[&str]) -> anyhow::Result<String> {
        loop {
            let ev = self.next().await?;
            tracing::debug!("wpa_supplicant: {ev}");
            if names.iter().any(|n| ev.split(' ').next() == Some(*n)) {
                return Ok(ev);
            }
        }
    }
}

/// Splits an event's `key=value` and `key="quoted value"` fields. Bare words
/// go in under their position ("0", "1", ...).
pub fn fields(event: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = event.trim();
    let mut pos = 0;
    while !rest.is_empty() {
        let (token, after) = match rest.find([' ', '"']) {
            Some(i) if rest.as_bytes()[i] == b'"' => {
                // key="value with spaces"
                let close = rest[i + 1..].find('"').map(|j| i + 1 + j).unwrap_or(rest.len());
                (&rest[..(close + 1).min(rest.len())], &rest[(close + 1).min(rest.len())..])
            }
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        match token.split_once('=') {
            Some((k, v)) => {
                let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
                out.insert(k.to_owned(), v.to_owned());
            }
            None => {
                out.insert(pos.to_string(), token.to_owned());
                pos += 1;
            }
        }
        rest = after.trim_start();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_group_started() {
        let f = fields(
            r#"P2P-GROUP-STARTED nc0 GO ssid="DIRECT-ab x" freq=2412 passphrase="s3cr3tpw" go_dev_addr=02:00:00:00:01:00"#,
        );
        assert_eq!(f["0"], "P2P-GROUP-STARTED");
        assert_eq!(f["1"], "nc0");
        assert_eq!(f["2"], "GO");
        assert_eq!(f["ssid"], "DIRECT-ab x");
        assert_eq!(f["freq"], "2412");
        assert_eq!(f["passphrase"], "s3cr3tpw");
        assert_eq!(f["go_dev_addr"], "02:00:00:00:01:00");
    }
}
