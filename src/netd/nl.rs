//! The nl80211 calls nearcast-netd needs: listing wireless interfaces,
//! adding or removing one, and reading a wiphy's channels and interface
//! combinations.

use anyhow::Context;
use futures_util::TryStreamExt;
use wl_nl80211::{
    Nl80211Attr, Nl80211BandInfo, Nl80211FrequencyInfo, Nl80211Handle, Nl80211IfaceCombAttribute,
    Nl80211IfaceCombLimitAttribute, Nl80211InterfaceType, Nl80211NewInterface,
};

#[derive(Debug, Clone)]
pub struct Iface {
    pub wiphy: u32,
    pub wdev: u64,
    pub index: Option<u32>,
    pub name: Option<String>,
    pub kind: Nl80211InterfaceType,
    pub mac: Option<[u8; 6]>,
    /// The operating frequency in MHz, for an interface that has one.
    pub freq: Option<u32>,
}

/// A channel the wiphy supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    pub freq: u32,
    /// The regulatory domain lets us start a group here: the channel isn't
    /// disabled and allows initiating radiation (no NO_IR flag).
    pub usable: bool,
    /// NL80211_FREQUENCY_ATTR_IR_CONCURRENT: starting a group here is
    /// allowed while connected to an access point on the same channel
    /// (on 5 GHz, in the same UNII band) that isn't a radar channel.
    pub ir_concurrent: bool,
}

/// What a wiphy can do for a Wi-Fi Direct group.
#[derive(Debug, Clone, Default)]
pub struct WiphyInfo {
    pub channels: Vec<Channel>,
    /// How many different channels the wiphy can use at once in an
    /// interface combination that includes a P2P group owner.
    pub go_channels: u32,
}

pub struct Nl {
    handle: Nl80211Handle,
}

impl Nl {
    pub fn new() -> anyhow::Result<Self> {
        let (conn, handle, _) = wl_nl80211::new_connection().context("opening nl80211")?;
        tokio::spawn(conn);
        Ok(Self { handle })
    }

    pub async fn interfaces(&self) -> anyhow::Result<Vec<Iface>> {
        let handle = self.handle.clone();
        let mut stream = handle.interface().get(vec![]).execute().await;
        let mut out = Vec::new();
        while let Some(msg) = stream.try_next().await? {
            let mut i = Iface {
                wiphy: 0,
                wdev: 0,
                index: None,
                name: None,
                kind: Nl80211InterfaceType::Unspecified,
                mac: None,
                freq: None,
            };
            for a in msg.payload.attributes {
                match a {
                    Nl80211Attr::Wiphy(w) => i.wiphy = w,
                    Nl80211Attr::Wdev(w) => i.wdev = w,
                    Nl80211Attr::IfIndex(x) => i.index = Some(x),
                    Nl80211Attr::IfName(n) => i.name = Some(n),
                    Nl80211Attr::IfType(t) => i.kind = t,
                    Nl80211Attr::Mac(m) => i.mac = Some(m),
                    Nl80211Attr::WiphyFreq(f) => i.freq = Some(f),
                    _ => {}
                }
            }
            out.push(i);
        }
        Ok(out)
    }

    pub async fn wiphy(&self, wiphy: u32) -> anyhow::Result<WiphyInfo> {
        let handle = self.handle.clone();
        let mut stream = handle.wireless_physic().get().wiphy_index(wiphy).execute().await;
        let mut info = WiphyInfo::default();
        // A split dump spreads the bands and combinations over several messages.
        while let Some(msg) = stream.try_next().await? {
            for a in msg.payload.attributes {
                match a {
                    Nl80211Attr::WiphyBands(bands) => {
                        for b in bands {
                            for bi in b.info {
                                let Nl80211BandInfo::Freqs(freqs) = bi else { continue };
                                for f in freqs {
                                    let Some(freq) = f.info.iter().find_map(|i| match i {
                                        Nl80211FrequencyInfo::Freq(x) => Some(*x),
                                        _ => None,
                                    }) else {
                                        continue;
                                    };
                                    let usable = !f.info.iter().any(|i| {
                                        matches!(
                                            i,
                                            Nl80211FrequencyInfo::Disabled
                                                | Nl80211FrequencyInfo::NoIr
                                                | Nl80211FrequencyInfo::NoIbss
                                        )
                                    });
                                    let ir_concurrent = f.info.iter().any(|i| {
                                        matches!(i, Nl80211FrequencyInfo::IrConcurrent)
                                    }) && !f.info.iter().any(|i| {
                                        matches!(i, Nl80211FrequencyInfo::Disabled | Nl80211FrequencyInfo::Radar)
                                    });
                                    info.channels.push(Channel { freq, usable, ir_concurrent });
                                }
                            }
                        }
                    }
                    Nl80211Attr::InterfaceCombination(combs) => {
                        for c in combs {
                            let has_go = c.attributes.iter().any(|a| match a {
                                Nl80211IfaceCombAttribute::Limits(ls) => ls.iter().any(|l| {
                                    l.attributes.iter().any(|la| {
                                        matches!(la, Nl80211IfaceCombLimitAttribute::Iftypes(t)
                                            if t.contains(&Nl80211InterfaceType::P2pGo))
                                    })
                                }),
                                _ => false,
                            });
                            let n = c.attributes.iter().find_map(|a| match a {
                                Nl80211IfaceCombAttribute::NumChannels(n) => Some(*n),
                                _ => None,
                            });
                            if let (true, Some(n)) = (has_go, n) {
                                info.go_channels = info.go_channels.max(n);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        info.channels.sort_by_key(|c| c.freq);
        info.channels.dedup_by_key(|c| c.freq);
        Ok(info)
    }

    pub async fn add(&self, wiphy: u32, name: &str, kind: Nl80211InterfaceType) -> anyhow::Result<()> {
        let handle = self.handle.clone();
        let attrs = Nl80211NewInterface::new(wiphy, kind, name.to_owned()).build();
        let mut stream = handle.interface().add(attrs).execute().await;
        while stream.try_next().await?.is_some() {}
        Ok(())
    }

    /// Removes an interface, or a device without a network interface (such
    /// as a P2P device), by its wdev ID.
    pub async fn delete(&self, wdev: u64) -> anyhow::Result<()> {
        let handle = self.handle.clone();
        let mut stream = handle.interface().delete(vec![Nl80211Attr::Wdev(wdev)]).execute().await;
        while stream.try_next().await?.is_some() {}
        Ok(())
    }
}
