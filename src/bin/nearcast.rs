use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand, ValueEnum};
use nearcast::ipc::{Client, Direction, Message, Request, Transfer, TransferState};
use nearcast::share::WifiSecurity;

/// Share files and text with nearby Android devices (Quick Share).
#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show this device and its transfers
    Status,
    /// List devices nearby
    Devices {
        /// Seconds to look for
        #[arg(short, long, default_value_t = 5)]
        wait: u64,
    },
    /// Send files and/or text to a device, by name or ID
    Send {
        to: String,
        files: Vec<PathBuf>,
        /// Text or a link to send
        #[arg(short, long)]
        text: Option<String>,
    },
    /// Wait for incoming shares and ask before accepting each
    Receive {
        /// Accept everything without asking
        #[arg(short, long)]
        yes: bool,
    },
    /// Accept an incoming share
    Accept { id: String },
    /// Reject an incoming share
    Reject { id: String },
    /// Cancel a transfer
    Cancel { id: String },
    /// Show or change whether other devices can see this one
    Visible { state: Option<OnOff> },
}

#[derive(Clone, Copy, ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Args::parse().cmd).await {
        eprintln!("nearcast: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cmd: Cmd) -> anyhow::Result<()> {
    let mut c = Client::connect().await?;
    match cmd {
        Cmd::Status => status(&mut c).await,
        Cmd::Devices { wait } => devices(&mut c, wait).await,
        Cmd::Send { to, files, text } => send(c, to, files, text).await,
        Cmd::Receive { yes } => receive(c, yes).await,
        Cmd::Accept { id } => c.call(&Request::Accept { id }).await.map(drop),
        Cmd::Reject { id } => c.call(&Request::Reject { id }).await.map(drop),
        Cmd::Cancel { id } => c.call(&Request::Cancel { id }).await.map(drop),
        Cmd::Visible { state: Some(s) } => {
            c.call(&Request::SetVisible { visible: matches!(s, OnOff::On) }).await.map(drop)
        }
        Cmd::Visible { state: None } => match c.call(&Request::Status).await? {
            Message::Status { visible, .. } => {
                println!("{}", if visible { "on" } else { "off" });
                Ok(())
            }
            m => bail!("unexpected reply {m:?}"),
        },
    }
}

fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

fn security_name(s: WifiSecurity) -> &'static str {
    match s {
        WifiSecurity::Open => "open",
        WifiSecurity::WpaPsk => "WPA",
        WifiSecurity::Wep => "WEP",
        WifiSecurity::Unknown => "unknown security",
    }
}

fn describe(t: &Transfer) -> String {
    let mut parts = Vec::new();
    match t.files.len() {
        0 => {}
        1 => parts.push(format!("{} ({})", t.files[0].name, human(t.files[0].size))),
        n => parts.push(format!("{n} files ({})", human(t.files.iter().map(|f| f.size).sum()))),
    }
    for text in &t.texts {
        let kind = format!("{:?}", text.kind).to_lowercase();
        parts.push(format!("{kind} \"{}\"", text.title));
    }
    for w in &t.wifi {
        parts.push(format!("Wi-Fi network \"{}\" ({})", w.ssid, security_name(w.security)));
    }
    parts.join(" and ")
}

async fn status(c: &mut Client) -> anyhow::Result<()> {
    let Message::Status { name, endpoint_id, visible, port, download_dir, transfers } =
        c.call(&Request::Status).await?
    else {
        bail!("unexpected reply");
    };
    println!("name:      {name} ({endpoint_id})");
    println!("visible:   {}", if visible { "yes" } else { "no" });
    println!("port:      {port}");
    println!("downloads: {}", download_dir.display());
    for t in transfers {
        let dir = if t.direction == Direction::Incoming { "from" } else { "to" };
        let err = t.error.as_ref().map(|e| format!(": {e}")).unwrap_or_default();
        println!("{}  {dir} {}  {}  {:?}{err}", t.id, t.peer, describe(&t), t.state);
    }
    Ok(())
}

async fn devices(c: &mut Client, wait: u64) -> anyhow::Result<()> {
    c.call(&Request::Discover).await?;
    let mut seen = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let m = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            m = c.next() => m?.context("nearcastd closed the connection")?,
        };
        if let Message::DeviceFound { device } = m
            && seen.insert(device.id.clone()) {
                println!("{}  {:<24} {:?}  {}", device.id, device.name, device.device_type, device.route);
            }
    }
    if seen.is_empty() {
        eprintln!("No devices found. On the other device, open Quick Share and make it visible to everyone.");
    }
    Ok(())
}

/// Prints a progress line, overwriting the previous one.
struct ProgressLine {
    start: Option<Instant>,
}

impl ProgressLine {
    fn show(&mut self, t: &Transfer) {
        let start = *self.start.get_or_insert_with(Instant::now);
        let pct = (t.bytes_done * 100).checked_div(t.bytes_total).unwrap_or(100);
        let secs = start.elapsed().as_secs_f64();
        let rate = if secs > 0.5 { format!("  {}/s", human((t.bytes_done as f64 / secs) as u64)) } else { String::new() };
        eprint!("\r\x1b[K  {pct:3}%  {} / {}{rate}", human(t.bytes_done), human(t.bytes_total));
        let _ = std::io::stderr().flush();
    }

    fn end(&mut self) {
        if self.start.take().is_some() {
            eprintln!();
        }
    }
}

async fn send(mut c: Client, to: String, files: Vec<PathBuf>, text: Option<String>) -> anyhow::Result<()> {
    if files.is_empty() && text.is_none() {
        bail!("give files to send and/or --text");
    }
    let files = files
        .iter()
        .map(|f| std::fs::canonicalize(f).with_context(|| format!("{}", f.display())))
        .collect::<anyhow::Result<Vec<_>>>()?;
    eprintln!("Looking for {to}…");
    let Message::Started { id } = c.call(&Request::Send { to, files, text }).await? else {
        bail!("unexpected reply");
    };

    let mut last_state = None;
    let mut progress = ProgressLine { start: None };
    let mut interrupted = false;
    loop {
        let m = tokio::select! {
            _ = tokio::signal::ctrl_c(), if !interrupted => {
                interrupted = true;
                c.send(&Request::Cancel { id: id.clone() }).await?;
                continue;
            }
            m = c.next() => m?.context("nearcastd closed the connection")?,
        };
        let t = match m {
            Message::Transfer { transfer } if transfer.id == id => transfer,
            Message::Error { message } => bail!(message),
            _ => continue,
        };
        if last_state != Some(t.state) {
            last_state = Some(t.state);
            match t.state {
                TransferState::Connecting => eprintln!("Connecting to {}…", t.peer),
                TransferState::WaitingForAccept => eprintln!(
                    "Waiting for {} to accept (PIN {})…",
                    t.peer,
                    t.pin.as_deref().unwrap_or("?")
                ),
                TransferState::Transferring => {}
                TransferState::Finished => {
                    progress.end();
                    eprintln!("Sent to {}.", t.peer);
                    return Ok(());
                }
                TransferState::Rejected => {
                    progress.end();
                    bail!("{} declined", t.peer);
                }
                TransferState::Cancelled => {
                    progress.end();
                    bail!("{}", t.error.as_deref().unwrap_or("cancelled"));
                }
                TransferState::Failed => {
                    progress.end();
                    bail!("{}", t.error.as_deref().unwrap_or("failed"));
                }
                TransferState::AwaitingDecision => {}
            }
        }
        if t.state == TransferState::Transferring {
            progress.show(&t);
        }
    }
}

/// Lines typed on stdin, read by one thread for the whole session.
fn stdin_lines() -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

async fn receive(mut c: Client, yes: bool) -> anyhow::Result<()> {
    let Message::Status { name, visible, download_dir, .. } = c.call(&Request::Status).await? else {
        bail!("unexpected reply");
    };
    c.call(&Request::Watch).await?;
    eprintln!(
        "Receiving as \"{name}\" into {}{}. Press Ctrl-C to stop.",
        download_dir.display(),
        if visible { "" } else { " (hidden: run `nearcast visible on`)" }
    );

    let mut input = (!yes).then(stdin_lines);
    let mut asked = HashSet::new();
    let mut done = HashSet::new();
    let mut progress = ProgressLine { start: None };
    // The transfer we are asking about, and the ones waiting their turn.
    let mut pending: Option<String> = None;
    let mut queue: Vec<Transfer> = Vec::new();
    loop {
        if pending.is_none()
            && let Some(t) = queue.pop() {
                let what = format!("{} (PIN {})", describe(&t), t.pin.as_deref().unwrap_or("?"));
                match input.as_mut() {
                    None => {
                        eprintln!("{} is sending {what}.", t.peer);
                        c.send(&Request::Accept { id: t.id }).await?;
                    }
                    Some(lines) => {
                        while lines.try_recv().is_ok() {} // drop anything typed earlier
                        eprint!("{} wants to send {what}. Accept? [y/N] ", t.peer);
                        let _ = std::io::stderr().flush();
                        pending = Some(t.id);
                    }
                }
            }
        let m = tokio::select! {
            _ = tokio::signal::ctrl_c() => { progress.end(); return Ok(()); }
            line = async { input.as_mut().expect("asking needs stdin").recv().await }, if pending.is_some() => {
                let id = pending.take().expect("checked");
                let yes = line.is_some_and(|l| matches!(l.trim(), "y" | "Y" | "yes"));
                c.send(&if yes { Request::Accept { id } } else { Request::Reject { id } }).await?;
                continue;
            }
            m = c.next() => m?.context("nearcastd closed the connection")?,
        };
        let t = match m {
            Message::Transfer { transfer } if transfer.direction == Direction::Incoming => transfer,
            Message::Error { message } => {
                eprintln!("nearcast: {message}");
                continue;
            }
            _ => continue,
        };
        if done.contains(&t.id) {
            continue;
        }
        match t.state {
            TransferState::AwaitingDecision if asked.insert(t.id.clone()) => queue.insert(0, t),
            TransferState::Transferring => progress.show(&t),
            TransferState::Finished => {
                progress.end();
                done.insert(t.id.clone());
                for p in &t.saved {
                    println!("{}", p.display());
                }
                for text in t.texts.iter().filter_map(|x| x.content.as_ref()) {
                    eprintln!("Text from {}:", t.peer);
                    println!("{text}");
                }
                // Shown, not added: joining the network is up to the user.
                for w in &t.wifi {
                    eprintln!("Wi-Fi network from {}:", t.peer);
                    println!("ssid: {}", w.ssid);
                    println!("security: {}", security_name(w.security));
                    if let Some(p) = w.password.as_deref().filter(|p| !p.is_empty()) {
                        println!("password: {p}");
                    }
                    if w.hidden {
                        println!("hidden: yes");
                    }
                }
            }
            TransferState::Rejected | TransferState::Cancelled | TransferState::Failed => {
                progress.end();
                done.insert(t.id.clone());
                // A transfer that ends while we are asking about it.
                if pending.as_ref() == Some(&t.id) {
                    pending = None;
                    eprintln!();
                }
                queue.retain(|q| q.id != t.id);
                let why = t.error.unwrap_or_else(|| format!("{:?}", t.state).to_lowercase());
                eprintln!("Share from {} ended: {why}", t.peer);
            }
            _ => {}
        }
    }
}
