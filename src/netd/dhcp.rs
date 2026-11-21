//! Just enough DHCP (RFC 2131) for a Wi-Fi Direct group: a server that hands
//! the one or two peers of a group we host an address, and a client that gets
//! one from a group we join. Both use UDP sockets bound to the group
//! interface, and ask for broadcast replies so nothing is sent to an address
//! the client doesn't have yet.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{bail, Context};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
const LEASE_SECS: u32 = 3600;

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

const OPT_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_REQUESTED: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_TYPE: u8 = 53;
const OPT_SERVER: u8 = 54;
const OPT_END: u8 = 255;

#[derive(Debug, Clone, Default)]
struct Packet {
    op: u8,
    xid: u32,
    flags: u16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    chaddr: [u8; 6],
    options: Vec<(u8, Vec<u8>)>,
}

impl Packet {
    fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 240 || b[236..240] != MAGIC || b[1] != 1 || b[2] != 6 {
            return None;
        }
        let ip = |i: usize| <[u8; 4]>::try_from(&b[i..i + 4]).unwrap();
        let mut p = Packet {
            op: b[0],
            xid: u32::from_be_bytes(ip(4)),
            flags: u16::from_be_bytes([b[10], b[11]]),
            ciaddr: ip(12),
            yiaddr: ip(16),
            siaddr: ip(20),
            chaddr: b[28..34].try_into().unwrap(),
            options: vec![],
        };
        let mut i = 240;
        while i < b.len() {
            match b[i] {
                0 => i += 1,
                OPT_END => break,
                code => {
                    let len = *b.get(i + 1)? as usize;
                    let val = b.get(i + 2..i + 2 + len)?;
                    p.options.push((code, val.to_vec()));
                    i += 2 + len;
                }
            }
        }
        Some(p)
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[0] = self.op;
        b[1] = 1; // Ethernet
        b[2] = 6;
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        b[10..12].copy_from_slice(&self.flags.to_be_bytes());
        b[12..16].copy_from_slice(&self.ciaddr);
        b[16..20].copy_from_slice(&self.yiaddr);
        b[20..24].copy_from_slice(&self.siaddr);
        b[28..34].copy_from_slice(&self.chaddr);
        b[236..240].copy_from_slice(&MAGIC);
        for (code, val) in &self.options {
            b.push(*code);
            b.push(val.len() as u8);
            b.extend_from_slice(val);
        }
        b.push(OPT_END);
        // Some clients drop replies shorter than a BOOTP packet.
        b.resize(b.len().max(300), 0);
        b
    }

    fn option(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }

    fn kind(&self) -> Option<u8> {
        self.option(OPT_TYPE).and_then(|v| v.first().copied())
    }

    fn addr_option(&self, code: u8) -> Option<Ipv4Addr> {
        let v: [u8; 4] = self.option(code)?.try_into().ok()?;
        Some(v.into())
    }
}

fn socket(iface: &str, port: u16) -> anyhow::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.bind_device(Some(iface.as_bytes())).context("binding to the group interface")?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(UdpSocket::from_std(s.into())?)
}

fn broadcast(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::BROADCAST, port)
}

/// Serves addresses `.2` to `.254` of `server`'s /24 on `iface` until
/// dropped.
pub async fn serve(iface: &str, server: Ipv4Addr) -> anyhow::Result<()> {
    let sock = socket(iface, SERVER_PORT)?;
    let net = server.octets();
    let mut leases: HashMap<[u8; 6], Ipv4Addr> = HashMap::new();
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, _) = sock.recv_from(&mut buf).await?;
        let Some(req) = Packet::parse(&buf[..n]) else { continue };
        if req.op != 1 {
            continue;
        }
        let next = (2..=254u8)
            .map(|h| Ipv4Addr::new(net[0], net[1], net[2], h))
            .find(|a| !leases.values().any(|l| l == a));
        let reply_type = match req.kind() {
            Some(DISCOVER) => {
                let Some(addr) = leases.get(&req.chaddr).copied().or(next) else { continue };
                leases.insert(req.chaddr, addr);
                (OFFER, addr)
            }
            Some(REQUEST) => {
                if req.addr_option(OPT_SERVER).is_some_and(|s| s != server) {
                    // The client chose another server.
                    leases.remove(&req.chaddr);
                    continue;
                }
                let wanted = req
                    .addr_option(OPT_REQUESTED)
                    .or_else(|| Some(Ipv4Addr::from(req.ciaddr)).filter(|a| !a.is_unspecified()));
                match (leases.get(&req.chaddr).copied(), wanted) {
                    (Some(l), Some(w)) if l == w => (ACK, l),
                    (None, Some(w))
                        if w.octets()[..3] == net[..3]
                            && w != server
                            && !leases.values().any(|l| *l == w) =>
                    {
                        leases.insert(req.chaddr, w);
                        (ACK, w)
                    }
                    _ => (NAK, Ipv4Addr::UNSPECIFIED),
                }
            }
            _ => continue,
        };
        let (kind, addr) = reply_type;
        let mut options = vec![(OPT_TYPE, vec![kind]), (OPT_SERVER, server.octets().to_vec())];
        if kind != NAK {
            options.push((OPT_LEASE, LEASE_SECS.to_be_bytes().to_vec()));
            options.push((OPT_MASK, vec![255, 255, 255, 0]));
        }
        let reply = Packet {
            op: 2,
            xid: req.xid,
            flags: req.flags,
            yiaddr: addr.octets(),
            siaddr: server.octets(),
            chaddr: req.chaddr,
            options,
            ..Default::default()
        };
        tracing::debug!("DHCP {kind} {addr} to {:02x?}", req.chaddr);
        sock.send_to(&reply.encode(), broadcast(CLIENT_PORT)).await?;
    }
}

/// An address the server leased us.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub server: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
}

/// Gets an address on `iface` with DISCOVER, OFFER, REQUEST and ACK,
/// resending each request a few times.
pub async fn request(iface: &str, mac: [u8; 6]) -> anyhow::Result<Lease> {
    let sock = socket(iface, CLIENT_PORT)?;
    let xid: u32 = rand::random();
    let base = Packet { op: 1, xid, flags: 0x8000, chaddr: mac, ..Default::default() };

    let discover = Packet { options: vec![(OPT_TYPE, vec![DISCOVER])], ..base.clone() };
    let offer = exchange(&sock, &discover, |p| p.kind() == Some(OFFER)).await.context("no DHCP offer")?;
    let server = offer
        .addr_option(OPT_SERVER)
        .unwrap_or_else(|| Ipv4Addr::from(offer.siaddr));

    let request = Packet {
        options: vec![
            (OPT_TYPE, vec![REQUEST]),
            (OPT_REQUESTED, offer.yiaddr.to_vec()),
            (OPT_SERVER, server.octets().to_vec()),
        ],
        ..base
    };
    let ack = exchange(&sock, &request, |p| matches!(p.kind(), Some(ACK) | Some(NAK)))
        .await
        .context("no DHCP acknowledgement")?;
    if ack.kind() == Some(NAK) {
        bail!("DHCP request refused");
    }
    let mask = ack.addr_option(OPT_MASK).map(u32::from).unwrap_or(0xffff_ff00);
    Ok(Lease {
        address: ack.yiaddr.into(),
        prefix: mask.count_ones() as u8,
        server,
        router: ack.addr_option(OPT_ROUTER),
    })
}

/// Broadcasts `p` and waits for a matching reply, resending up to four
/// times at growing intervals.
async fn exchange(sock: &UdpSocket, p: &Packet, want: impl Fn(&Packet) -> bool) -> anyhow::Result<Packet> {
    let bytes = p.encode();
    let mut buf = vec![0u8; 1500];
    for wait in [1, 2, 4, 8] {
        sock.send_to(&bytes, broadcast(SERVER_PORT)).await?;
        let deadline = tokio::time::sleep(Duration::from_secs(wait));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = sock.recv_from(&mut buf) => {
                    let (n, _) = r?;
                    if let Some(reply) = Packet::parse(&buf[..n])
                        && reply.op == 2 && reply.xid == p.xid && reply.chaddr == p.chaddr && want(&reply) {
                            return Ok(reply);
                        }
                }
            }
        }
    }
    bail!("timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip() {
        let p = Packet {
            op: 1,
            xid: 0x1234_5678,
            flags: 0x8000,
            chaddr: [1, 2, 3, 4, 5, 6],
            yiaddr: [192, 168, 49, 7],
            options: vec![(OPT_TYPE, vec![REQUEST]), (OPT_REQUESTED, vec![192, 168, 49, 7])],
            ..Default::default()
        };
        let q = Packet::parse(&p.encode()).unwrap();
        assert_eq!(q.xid, p.xid);
        assert_eq!(q.flags, 0x8000);
        assert_eq!(q.chaddr, p.chaddr);
        assert_eq!(q.yiaddr, p.yiaddr);
        assert_eq!(q.kind(), Some(REQUEST));
        assert_eq!(q.addr_option(OPT_REQUESTED), Some(Ipv4Addr::new(192, 168, 49, 7)));
    }
}
