use std::path::PathBuf;

use clap::Parser;
use nearcast::proto::connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;

/// Quick Share daemon: receives shares and sends them on behalf of nearcast.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Name shown to other devices [default: the host name]
    #[arg(long)]
    name: Option<String>,
    /// Where received files go [default: "Quick Share" in the XDG download directory]
    #[arg(long)]
    download_dir: Option<PathBuf>,
    /// Start hidden from other devices
    #[arg(long)]
    hidden: bool,
    /// TCP port for incoming transfers [default: any free port]
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Don't advertise or discover on the local network (Bluetooth only)
    #[arg(long)]
    no_lan: bool,
    /// Mediums to upgrade connections to, most preferred first
    #[arg(long, value_enum, value_delimiter = ',', default_value = "lan,wifi-direct,hotspot")]
    upgrade: Vec<Upgrade>,
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Upgrade {
    /// The local network (TCP)
    Lan,
    /// Wi-Fi Direct, through nearcast-netd
    WifiDirect,
    /// A hotspot for the other device to join (hosting only), through nearcast-netd
    Hotspot,
    /// No upgrades
    None,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| {
        hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "Linux".into())
    });
    let download_dir = args.download_dir.unwrap_or_else(|| {
        directories::UserDirs::new()
            .map(|u| u.download_dir().unwrap_or(u.home_dir()).join("Quick Share"))
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let upgrades = args
        .upgrade
        .iter()
        .filter_map(|u| match u {
            Upgrade::Lan => Some(Medium::WifiLan),
            Upgrade::WifiDirect => Some(Medium::WifiDirect),
            Upgrade::Hotspot => Some(Medium::WifiHotspot),
            Upgrade::None => None,
        })
        .collect();
    nearcast::daemon::run(nearcast::daemon::Config { name, download_dir, visible: !args.hidden, port: args.port, lan: !args.no_lan, upgrades })
        .await
}
