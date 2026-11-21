//! nearcast-netd: the system service that sets up Wi-Fi Direct groups for
//! nearcastd. See `nearcast::netd`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::Parser;
use nearcast::netd::{service::Netd, Backend, BUS_NAME, OBJECT_PATH};
use tokio::signal::unix::{signal, SignalKind};

#[derive(Parser)]
#[command(about = "Sets up Wi-Fi Direct groups for nearcastd")]
struct Args {
    /// Which wpa_supplicant runs the groups: `system` uses the one already
    /// managing the station interface (NetworkManager, wpa_supplicant.service)
    /// over D-Bus, `private` starts netd's own on a separate interface, and
    /// `auto` uses the system one when it manages the station interface.
    #[arg(long, value_enum, default_value = "auto")]
    wpa_supplicant: Backend,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .with_ansi(false)
        .init();

    // systemd's RuntimeDirectory= sets this; wpa_supplicant's control
    // sockets and config go there.
    let dir = std::env::var_os("RUNTIME_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/nearcast-netd"));
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let netd = Netd::new(dir, args.wpa_supplicant)?;
    let _conn = zbus::connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, netd.clone())?
        .build()
        .await?;
    tracing::info!("serving {BUS_NAME} (wpa_supplicant: {:?})", args.wpa_supplicant);

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    netd.shutdown().await;
    Ok(())
}
