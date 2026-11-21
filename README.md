# nearcast

**Quick Share for Linux.** nearcast makes a Linux computer show up in the
Quick Share sheet of Android phones (Google's Quick Share, formerly Nearby
Share, and Samsung's Quick Share), and lets it share back to them. Files,
text and Wi-Fi networks go both ways, over the local network, over Bluetooth
when there is no network, and over Wi-Fi Direct for speed. No app is needed
on the phone and no Google account on the computer.

It is a small per-user daemon, `nearcastd`, with a command-line client,
`nearcast`; front ends can drive the same daemon over a local socket. It
speaks Google's Nearby Connections and Nearby Sharing protocol the way phones
do, in "everyone" visibility mode. nearcast is inspired by
[rquickshare](https://github.com/Martichou/rquickshare).

<p align="center">
  <img src="docs/media/demo.gif" alt="nearcast listing devices, sending a video and accepting two photos" width="720">
</p>

## Features

Sending and receiving work both ways on a shared network: files, several files
at once, text, and files plus text in one share, with accept, decline and
cancel from either side showing up correctly on the phone. Shared Wi-Fi
networks are received too; nearcast shows the name, security and password and
leaves it to you (or a front end) whether to add the network.

With no shared network, phones can send to the computer over Bluetooth. The
connection then moves to the local network or to a Wi-Fi Direct group that
nearcast hosts, which in testing ran about 35 times faster than Bluetooth.

nearcast follows the system's state rather than polling it: it re-advertises
when the Bluetooth adapter resets (suspend and resume) or bluetoothd restarts,
and keeps its identity across a quick restart so phones don't list the
computer twice. It doesn't depend on NetworkManager.

## Status

nearcast is young. It is tested with a Samsung Galaxy S24 FE and an Intel
8265 (Bluetooth 4.2) laptop.

| Path | Needs | State |
|---|---|---|
| Same network, both ways | a network | works |
| Phone to computer over Bluetooth | Bluetooth LE and Classic | works |
| Computer to phone over Bluetooth | a Bluetooth 5 adapter | built, untested |
| Wi-Fi Direct, phone to computer | `nearcast-netd`, wpa_supplicant | works |
| Wi-Fi Direct, computer to phone | the same, plus a Bluetooth 5 adapter | built, untested |
| Hotspot upgrade | `nearcast-netd` | hosted, but phones refuse to join it |

Recent phones in "everyone" mode only announce themselves in Bluetooth 5
extended advertisements, which a Bluetooth 4.x adapter can't receive, so
sending to a phone with no shared network needs a Bluetooth 5 adapter.

## Install

nearcast needs Rust, `protoc` (protobuf), BlueZ, and for Wi-Fi Direct
wpa_supplicant built with P2P support (Arch's is). Build and install to
`/usr/local`:

```bash
make
```

```bash
sudo make install
```

`make PREFIX=/usr DESTDIR=pkg install` stages a package instead. Then reload
systemd and D-Bus and start the daemon as your user:

```bash
sudo systemctl daemon-reload
```

```bash
systemctl --user enable --now nearcastd
```

`nearcast-netd` doesn't need enabling; D-Bus starts it when nearcastd first
asks for Wi-Fi Direct, and polkit lets active local sessions use it without a
password.

## Use

```bash
nearcast devices                       # who is around (their Quick Share must be open)
nearcast send "Pixel 9" photo.jpg      # by name or ID
nearcast send AB12 --text https://example.com
nearcast receive                       # ask before accepting each share
nearcast status
nearcast visible off
```

Received files go to `Quick Share` in your download directory
(`~/Downloads/Quick Share`), as on Android. `nearcastd --help` lists the
daemon's options: the name shown to phones, the download directory, starting
hidden, Bluetooth only (`--no-lan`), and which upgrades to offer
(`--upgrade lan,wifi-direct,hotspot`, the default, or `none`).

## Bluetooth setup

Two prompts can appear the first time a phone sends over Bluetooth. On the
phone, BlueZ's LE Audio client plugins read the phone's protected services
when it connects, and the phone asks to pair. Setting

```ini
[GATT]
Client = false
```

in `/etc/bluetooth/main.conf` stops that, at the cost of BlueZ's GATT client
for devices that connect to the computer (see
[bluez/bluez#1789](https://github.com/bluez/bluez/issues/1789)). On the
computer, the kernel asks you to confirm the first Bluetooth Classic
connection from an unpaired phone; accept it and the transfer completes.

## Wi-Fi Direct

nearcastd runs as you, so the radio work goes through `nearcast-netd`, a
small system service on D-Bus. Where the system wpa_supplicant already
manages Wi-Fi (NetworkManager, `wpa_supplicant@.service`), netd asks it for
the group over D-Bus. Otherwise it starts a private wpa_supplicant on an
interface of its own, which works next to iwd. `--wpa-supplicant
auto|system|private` (through a drop-in for `nearcast-netd.service`) forces
either.

The group goes on the station's channel when the regulatory domain allows it,
and on a 2.4 GHz social channel otherwise. Set your regulatory country
(`iw reg set XX`, or your distribution's setting) so that 5 GHz channels are
usable. With an active firewall, allow DHCP (UDP 67) and incoming TCP on the
group interface.

## Front ends

`nearcastd` listens on `$XDG_RUNTIME_DIR/nearcast.sock`, one JSON message per
line, described in [`src/ipc.rs`](src/ipc.rs). `{"cmd":"watch"}` streams
every event.

## Roadmap

A graphical front end, and testing the Bluetooth 5 paths. Possibly QR-code
sharing, which Google's open-source Nearby code shows needs no account.
Contacts-only and "your devices" visibility, and online sharing, need
certificates and servers that Google only offers to its own clients, so they
are unlikely.

## Contributing

[docs/HACKING.md](docs/HACKING.md) covers the code layout, testing against a
phone, and protocol behaviour the specifications leave out. Bug reports with
`RUST_LOG=nearcast=debug nearcastd` output and the phone model are welcome.

## Credits and license

nearcast is GPL-3.0-or-later. The protocol definitions in `proto/` come from
Google's Nearby and UKEY2 projects (Apache-2.0). Parts of the handshake and
payload handling started from
[rquickshare](https://github.com/Martichou/rquickshare) (GPL-3.0).
Chromium's Nearby Share and google/nearby were the references for protocol
behaviour.

Quick Share and Nearby Share are Google and Samsung trademarks; nearcast is
not affiliated with either.
