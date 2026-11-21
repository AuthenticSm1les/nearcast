//! Identity of a Nearby Sharing endpoint: endpoint ID, endpoint info and the
//! mDNS names derived from them.

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Nearby Connections service ID used by Quick Share.
pub const SERVICE_ID: &str = "NearbySharing";
/// First 3 bytes of SHA-256(SERVICE_ID).
pub const SERVICE_ID_HASH: [u8; 3] = [0xFC, 0x9F, 0x5E];
/// `_` + hex of the first 6 bytes of SHA-256(SERVICE_ID).
pub const MDNS_SERVICE_TYPE: &str = "_FC9F5ED42C8A._tcp.local.";
/// Version 1 (top 3 bits) and the P2P_POINT_TO_POINT strategy (low 5 bits).
pub const PCP_P2P_POINT_TO_POINT: u8 = 0x23;

/// Endpoint IDs are 4 characters from this alphabet.
const ENDPOINT_ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// Bytes before the name: 1 flag byte + 16 bytes salt/encrypted metadata key.
const INFO_HEADER_LEN: usize = 17;
/// Longest device name we put on the wire.
const MAX_NAME_LEN: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Unknown,
    Phone,
    Tablet,
    Laptop,
}

impl DeviceType {
    fn to_bits(self) -> u8 {
        match self {
            DeviceType::Unknown => 0,
            DeviceType::Phone => 1,
            DeviceType::Tablet => 2,
            DeviceType::Laptop => 3,
        }
    }

    fn from_bits(v: u8) -> Self {
        match v {
            1 => DeviceType::Phone,
            2 => DeviceType::Tablet,
            3 => DeviceType::Laptop,
            _ => DeviceType::Unknown,
        }
    }
}

pub fn random_endpoint_id() -> [u8; 4] {
    let mut rng = rand::rng();
    std::array::from_fn(|_| ENDPOINT_ID_ALPHABET[rng.random_range(0..ENDPOINT_ID_ALPHABET.len())])
}

/// How long after we stopped advertising a restart may keep our endpoint ID.
/// Nearby Connections does the same (`kAdvertisingKeepAliveDuration` in
/// google/nearby `connections/implementation/client_proxy.cc`), so a quick
/// restart doesn't leave phones showing us twice, while the ID still changes
/// once we've been gone a while.
pub const ENDPOINT_ID_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Milliseconds since boot, counting suspend, like Android's
/// `ElapsedRealtime` that Nearby Connections stores with the ID.
pub fn boot_millis() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .map(|t| t.tv_sec() as u64 * 1000 + t.tv_nsec() as u64 / 1_000_000)
        .unwrap_or(0)
}

/// Records the endpoint ID we were advertising with, for the next start.
pub fn save_endpoint_id(path: &std::path::Path, id: &[u8; 4], now_ms: u64) -> std::io::Result<()> {
    std::fs::write(path, format!("{} {now_ms}\n", String::from_utf8_lossy(id)))
}

/// Takes the ID `save_endpoint_id` left, if it was saved within
/// `ENDPOINT_ID_KEEP_ALIVE` and is well formed. The record is removed either
/// way, as Nearby Connections does.
pub fn load_endpoint_id(path: &std::path::Path, now_ms: u64) -> Option<[u8; 4]> {
    let text = std::fs::read_to_string(path).ok();
    let _ = std::fs::remove_file(path);
    let (id, at) = text?.trim().split_once(' ').map(|(a, b)| (a.to_owned(), b.to_owned()))?;
    let at: u64 = at.parse().ok()?;
    if now_ms < at || now_ms - at >= ENDPOINT_ID_KEEP_ALIVE.as_millis() as u64 {
        return None;
    }
    let id: [u8; 4] = id.as_bytes().try_into().ok()?;
    id.iter().all(|c| ENDPOINT_ID_ALPHABET.contains(c)).then_some(id)
}

/// Truncates to at most `max` bytes on a character boundary.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Nearby Sharing endpoint info for a visible ("everyone") device:
/// flags (version 0, visible, device type), 16 random bytes, name length, name.
pub fn encode_endpoint_info(device_type: DeviceType, name: &str) -> Vec<u8> {
    let name = truncate_utf8(name, MAX_NAME_LEN);
    let mut out = Vec::with_capacity(INFO_HEADER_LEN + 1 + name.len());
    out.push(device_type.to_bits() << 1);
    out.extend_from_slice(&rand::rng().random::<[u8; 16]>());
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out
}

/// Parses endpoint info; the name is absent for hidden (contacts-only) devices.
pub fn decode_endpoint_info(info: &[u8]) -> anyhow::Result<(DeviceType, Option<String>)> {
    if info.len() < INFO_HEADER_LEN {
        bail!("endpoint info too short ({} bytes)", info.len());
    }
    let device_type = DeviceType::from_bits((info[0] >> 1) & 0x7);
    if info.len() == INFO_HEADER_LEN {
        return Ok((device_type, None));
    }
    let len = info[INFO_HEADER_LEN] as usize;
    let name = info
        .get(INFO_HEADER_LEN + 1..INFO_HEADER_LEN + 1 + len)
        .context("endpoint info name truncated")?;
    let name = String::from_utf8(name.to_vec()).context("endpoint name is not UTF-8")?;
    Ok((device_type, Some(name)))
}

/// mDNS instance name: PCP, endpoint ID, service ID hash, 2 reserved bytes.
pub fn mdns_instance_name(endpoint_id: &[u8; 4]) -> String {
    let mut b = vec![PCP_P2P_POINT_TO_POINT];
    b.extend_from_slice(endpoint_id);
    b.extend_from_slice(&SERVICE_ID_HASH);
    b.extend_from_slice(&[0, 0]);
    URL_SAFE_NO_PAD.encode(b)
}

/// Endpoint ID from an mDNS instance name, if it is a Quick Share one.
pub fn parse_mdns_instance_name(name: &str) -> Option<[u8; 4]> {
    let b = URL_SAFE_NO_PAD.decode(name).ok()?;
    if b.len() < 8 || b[0] != PCP_P2P_POINT_TO_POINT || b[5..8] != SERVICE_ID_HASH {
        return None;
    }
    let id: [u8; 4] = b[1..5].try_into().ok()?;
    id.iter().all(u8::is_ascii_alphanumeric).then_some(id)
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoint_id_is_kept_only_across_a_quick_restart() {
        let dir = std::env::temp_dir().join(format!("nearcast-eid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endpoint");
        super::save_endpoint_id(&path, b"AB12", 1_000).unwrap();
        assert_eq!(super::load_endpoint_id(&path, 20_000), Some(*b"AB12"));
        // Taken once.
        assert_eq!(super::load_endpoint_id(&path, 20_000), None);
        super::save_endpoint_id(&path, b"AB12", 1_000).unwrap();
        assert_eq!(super::load_endpoint_id(&path, 31_000), None);
        // Saved before a reboot: the boot clock went backwards.
        super::save_endpoint_id(&path, b"AB12", 50_000).unwrap();
        assert_eq!(super::load_endpoint_id(&path, 2_000), None);
        std::fs::write(&path, "ab!2 1000\n").unwrap();
        assert_eq!(super::load_endpoint_id(&path, 2_000), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn service_constants_match_service_id() {
        let h = Sha256::digest(SERVICE_ID.as_bytes());
        assert_eq!(h[..3], SERVICE_ID_HASH);
        let ty: String = h[..6].iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(MDNS_SERVICE_TYPE, format!("_{ty}._tcp.local."));
    }

    #[test]
    fn endpoint_info_roundtrip() {
        let info = encode_endpoint_info(DeviceType::Laptop, "my laptop");
        let (t, n) = decode_endpoint_info(&info).unwrap();
        assert_eq!(t, DeviceType::Laptop);
        assert_eq!(n.as_deref(), Some("my laptop"));
    }

    #[test]
    fn long_names_truncate_on_char_boundary() {
        let name = "é".repeat(80);
        let info = encode_endpoint_info(DeviceType::Phone, &name);
        let (_, n) = decode_endpoint_info(&info).unwrap();
        assert_eq!(n.unwrap().len(), 100);
    }

    #[test]
    fn mdns_name_roundtrip() {
        let id = *b"AB12";
        assert_eq!(parse_mdns_instance_name(&mdns_instance_name(&id)), Some(id));
        assert_eq!(parse_mdns_instance_name("not-ours"), None);
    }
}
