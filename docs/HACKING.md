# Hacking on nearcast

Notes for working on the code: how it is laid out, how to test it against a
real phone, and protocol behaviour that the `.proto` files don't spell out.

## Principles

nearcast follows Google's Nearby Connections / Nearby Sharing protocol as
phones speak it, in "everyone" visibility mode. It doesn't invent protocol
behaviour: when a phone does something unexpected, find what the real
protocol does and match it. Chrome's Nearby Share
(`chrome/browser/nearby_sharing/` in Chromium, mainly
`nearby_sharing_service_impl.cc`) and google/nearby (`connections/` and
`sharing/`) are the references.

Nothing depends on one laptop, adapter or phone, and there is no
NetworkManager dependency. System services are reached over D-Bus and
followed through their signals (BlueZ through `bluer`, wpa_supplicant,
polkit); nothing shells out or polls. A timer is only used as a bounded retry
after a failure, and its comment says why.

## Layout

`src/wire.rs` handles framing and the secure channel, `src/ukey2.rs` the UKEY2
handshake, and `src/connection.rs` Nearby Connections over any byte stream
(TCP or RFCOMM). `src/upgrade.rs` negotiates bandwidth upgrades and
`src/mediums.rs` implements the mediums a connection can move to.
`src/share.rs` is Nearby Sharing on top: introduction, consent, file, text
and Wi-Fi payloads. `src/endpoint.rs` encodes the endpoint ID and info,
`src/mdns.rs` does LAN discovery and advertising, and `src/bluetooth.rs` BLE
discovery and advertising, the RFCOMM profile and the adapter monitor.
`src/daemon.rs` ties these together and `src/ipc.rs` is the front-end
protocol. `src/netd/` is nearcast-netd (`nl.rs` nl80211, `wpa.rs`
wpa_supplicant's control socket, `system.rs` its D-Bus API, `dhcp.rs` a
minimal DHCP server and client, `service.rs` the D-Bus interface). The
binaries are in `src/bin/`, Google's `.proto` files in `proto/` (compiled by
`build.rs`, which needs `protoc`), and the units, D-Bus and polkit files in
`packaging/`.

## Build and test

```bash
cargo build --release
cargo test --release
cargo clippy --release --all-targets
```

`packaging/install-netd-dev.sh` (run as root from the project directory)
installs a development build of nearcast-netd under `/usr/local`; it takes
`--uninstall`.

```bash
RUST_LOG=nearcast=debug,info ./target/release/nearcastd --no-lan
./target/release/nearcast receive --yes
```

`--no-lan` disables mDNS so a test can only succeed over Bluetooth. Samsung
Quick Share won't search with the phone's Wi-Fi off, so use this flag rather
than turning Wi-Fi off.

## Testing with a phone

Phone tests drive the phone over adb, USB or wireless debugging (wireless
drops whenever the phone's Wi-Fi does). The phone must be unlocked, since the
share intent does nothing on the lock screen. `tools/phone-send.sh` opens
Samsung Quick Share with a text share and taps this computer's entry; watch
the phone with `adb logcat -v time | grep -iE 'nearby|sharelive|rfcomm'`.

For file tests, push a file to `/sdcard/Download`, run the media scanner on
it, look up its `_id` with `content query --uri content://media/external/file`,
and start a SEND intent with
`--eu android.intent.extra.STREAM content://media/external/file/<id> -f 1`.
`am start` can't pass a list of URIs, so multi-file tests go through the file
manager's share action. For laptop to phone, open Quick Share's receive
screen and tap Accept (find `text="Accept"` in a `uiautomator dump`); files
land in `/sdcard/Download/Quick Share`. Compare SHA-256 on both sides.

## Protocol notes

**Rejecting and cancelling.** Don't close a connection right after a final
REJECT response or CANCEL frame. Android acts on the disconnection before it
has processed frames it already received, and reports a failed transfer
instead of a declined or cancelled one. `share.rs` does what Chrome does
(`kIncomingRejectionDelay` 2 s, `kInitiatorCancelDelay` 5 s): it keeps the
connection open for `REJECT_LINGER` or `CANCEL_LINGER`, closing sooner if the
peer hangs up. The daemon tracks those lingering connections and waits for
them, up to `SHUTDOWN_GRACE`, when it stops.

**Samsung's early ACCEPT.** Samsung sends a sharing RESPONSE (ACCEPT) frame
while the receiver is still waiting for the user, sometimes even before the
Introduction. `share::run_receive` ignores it in both places; the unit test
`early_response_before_introduction_is_ignored` covers it.

**What an introduction may carry.** Receiving accepts what Chrome accepts:
several files and texts, and Wi-Fi credentials (SSID and security in the
metadata, the password in a BYTES payload holding a `WifiCredentials`
message). nearcast never adds a received network; it passes it to the front
end. Unlike Chrome, it accepts empty files.

**Endpoint ID.** A restart within 30 s keeps the endpoint ID, as Nearby
Connections does (`kAdvertisingKeepAliveDuration` in
`connections/implementation/client_proxy.cc`); phones would otherwise list a
second entry until the old one ages out.

## Bluetooth notes

**RFCOMM channel.** BlueZ only listens on RFCOMM, and lists the channel in
the SDP record, for a custom-UUID external profile when a channel is given.
`channel: Some(0)` (any free channel) is required, or phones fail with
`scn: 0`.

**Pairing prompts.** On the phone, bluetoothd's LE Audio client plugins read
the phone's protected services when it connects for the GATT advertisement,
and the phone asks to pair. `[GATT] Client = false` in bluetoothd's
main.conf stops that (bluez/bluez#1789). On the computer, the kernel asks
the user to confirm the first Bluetooth Classic connection from an unpaired
phone (CVE-2024-8805), and accepting it lets the transfer complete.

**Advertising.** Right after power-on, bluetoothd sometimes never replies to
RegisterAdvertisement (bluez/bluez#2850); `ADVERTISE_TIMEOUT` and a backoff
retry in `daemon.rs` work around it. Extended advertising is only tried when
`LEAdvertisingManager1.SupportedFeatures` contains `HardwareOffload`, the
check Chrome uses. On a Bluetooth 4.x controller advertisement data is capped
at 31 bytes and nearcastd uses the legacy header plus GATT, which phones
handle. Recent phones in "everyone" mode advertise their own Nearby data only
in extended advertisements, so sending to a phone over Bluetooth (level 1)
needs a Bluetooth 5 adapter.

**Adapter resets.** Suspend/resume or a bluetoothd restart drops everything
registered on the adapter. `Bluetooth::monitor` follows BlueZ's signals and
the daemon advertises and registers its profile again.

## Bandwidth upgrades

The negotiation follows google/nearby's `bwu_manager.cc` and
`base_pcp_handler.cc`. The side that accepted the connection starts the
upgrade, so when nearcast receives it hosts and the phone joins; when it
sends, the phone hosts. On the new channel CLIENT_INTRODUCTION and its ACK go
in the clear, then the channel reuses the old one's keys and sequence
numbers. Each side sends LAST_WRITE_TO_PRIOR_CHANNEL on the old channel and
answers the peer's with SAFE_TO_CLOSE_PRIOR_CHANNEL after its own
LAST_WRITE. The unit tests `upgrades_to_another_medium_mid_connection` and
`stays_on_the_old_medium_when_the_peer_cant_join` run the whole negotiation
over loopback.

### nearcast-netd

nearcastd runs as the user, so Wi-Fi Direct goes through nearcast-netd, a
root system service on `org.nearcast.Netd1`, activated over D-Bus. Its
methods are `HostWifiDirect() -> (id, ssid, passphrase, freq, gateway)`,
`JoinWifiDirect(ssid, passphrase, freq) -> (id, address, gateway)`,
`Release(id)` and `Capabilities()`, each checked against the polkit action
`org.nearcast.netd.wifi-direct`. It runs one group at a time and takes it
down on Release, when the caller leaves the bus, or on SIGTERM.

`--wpa-supplicant auto|system|private` picks who runs the group. `system`
drives the system wpa_supplicant over D-Bus (`fi.w1.wpa_supplicant1`):
GroupAdd with `frequency` to host; AddPersistentGroup with the peer's
credentials, then GroupAdd with `persistent_group_object`, to join.
`private` starts netd's own wpa_supplicant on a separate interface, `nc0`;
since a radio has a single P2P device, it deletes one another daemon
created, which that daemon only gets back when it restarts. `auto` uses the
system instance when it manages the station interface.

Hosting adds 192.168.49.1/24 (the address Android uses for its groups) and
runs a DHCP server; joining gets an address over DHCP. The group's channel
comes from nl80211: the station's channel when the regulatory domain allows
starting a group there, outright or because it's IR-concurrent, otherwise a
2.4 GHz social channel. Sharing the station's channel matters: a group on a
second band next to a 5 GHz station has crashed an Intel 8265's firmware.

WIFI_HOTSPOT is offered with the same group (a group owner is a plain WPA2
access point to a station). Phones tested so far refuse to join it.
