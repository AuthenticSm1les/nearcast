//! UKEY2 handshake (P-256, SHA-512 commitment) and the D2D key derivation that
//! keys the secure channel. See google/ukey2 for the specification.

use anyhow::{bail, Context};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proto::securegcm::ukey2_alert::AlertType;
use crate::proto::securegcm::ukey2_client_init::CipherCommitment;
use crate::proto::securegcm::{
    ukey2_message, Ukey2Alert, Ukey2ClientFinished, Ukey2ClientInit, Ukey2HandshakeCipher,
    Ukey2Message, Ukey2ServerInit,
};
use crate::proto::securemessage::{EcP256PublicKey, GenericPublicKey, PublicKeyType};
use crate::wire::{read_frame, write_frame, DirectionKeys};

const NEXT_PROTOCOL: &str = "AES_256_CBC-HMAC_SHA256";

/// Result of a completed handshake.
pub struct Keys {
    pub send: DirectionKeys,
    pub recv: DirectionKeys,
    /// Authentication string; both sides derive the same PIN from it.
    pub auth: [u8; 32],
}

impl Keys {
    /// The 4-digit code both devices display.
    pub fn pin(&self) -> String {
        // Nearby Sharing's ToFourDigitString over the signed bytes.
        const MODULO: i32 = 9973;
        const BASE: i32 = 31;
        let mut hash = 0i32;
        let mut mult = 1i32;
        for &b in &self.auth {
            hash = (hash + (b as i8 as i32) * mult) % MODULO;
            mult = (mult * BASE) % MODULO;
        }
        format!("{:04}", hash.abs())
    }
}

#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

pub async fn client<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> anyhow::Result<Keys> {
    let secret = SecretKey::random(&mut OsRng);
    let finish = Ukey2Message {
        message_type: Some(ukey2_message::Type::ClientFinish.into()),
        message_data: Some(
            Ukey2ClientFinished { public_key: Some(encode_public_key(&secret.public_key())) }
                .encode_to_vec(),
        ),
    }
    .encode_to_vec();
    let init = Ukey2Message {
        message_type: Some(ukey2_message::Type::ClientInit.into()),
        message_data: Some(
            Ukey2ClientInit {
                version: Some(1),
                random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
                cipher_commitments: vec![CipherCommitment {
                    handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
                    commitment: Some(Sha512::digest(&finish).to_vec()),
                }],
                next_protocol: Some(NEXT_PROTOCOL.into()),
            }
            .encode_to_vec(),
        ),
    }
    .encode_to_vec();
    write_frame(s, &init).await?;

    let server_init_raw = read_frame(s).await?;
    let msg = Ukey2Message::decode(&*server_init_raw)?;
    if msg.message_type() == ukey2_message::Type::Alert {
        bail!("peer aborted the handshake: {:?}", Ukey2Alert::decode(msg.message_data()).ok());
    }
    if msg.message_type() != ukey2_message::Type::ServerInit {
        return alert(s, AlertType::BadMessageType).await;
    }
    let Ok(server_init) = Ukey2ServerInit::decode(msg.message_data()) else {
        return alert(s, AlertType::BadMessageData).await;
    };
    if server_init.version() != 1 {
        return alert(s, AlertType::BadVersion).await;
    }
    if server_init.random().len() != 32 {
        return alert(s, AlertType::BadRandom).await;
    }
    if server_init.handshake_cipher() != Ukey2HandshakeCipher::P256Sha512 {
        return alert(s, AlertType::BadHandshakeCipher).await;
    }
    let Ok(peer) = decode_public_key(server_init.public_key()) else {
        return alert(s, AlertType::BadPublicKey).await;
    };

    write_frame(s, &finish).await?;
    derive(&secret, &peer, &init, &server_init_raw, Role::Client)
}

pub async fn server<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> anyhow::Result<Keys> {
    let client_init_raw = read_frame(s).await?;
    let msg = Ukey2Message::decode(&*client_init_raw)?;
    if msg.message_type() != ukey2_message::Type::ClientInit {
        return alert(s, AlertType::BadMessageType).await;
    }
    let Ok(client_init) = Ukey2ClientInit::decode(msg.message_data()) else {
        return alert(s, AlertType::BadMessageData).await;
    };
    if client_init.version() != 1 {
        return alert(s, AlertType::BadVersion).await;
    }
    if client_init.random().len() != 32 {
        return alert(s, AlertType::BadRandom).await;
    }
    let Some(commitment) = client_init
        .cipher_commitments
        .iter()
        .find(|c| c.handshake_cipher() == Ukey2HandshakeCipher::P256Sha512)
        .map(|c| c.commitment().to_vec())
    else {
        return alert(s, AlertType::BadHandshakeCipher).await;
    };
    if client_init.next_protocol() != NEXT_PROTOCOL {
        return alert(s, AlertType::BadNextProtocol).await;
    }

    let secret = SecretKey::random(&mut OsRng);
    let server_init = Ukey2Message {
        message_type: Some(ukey2_message::Type::ServerInit.into()),
        message_data: Some(
            Ukey2ServerInit {
                version: Some(1),
                random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
                handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
                public_key: Some(encode_public_key(&secret.public_key())),
            }
            .encode_to_vec(),
        ),
    }
    .encode_to_vec();
    write_frame(s, &server_init).await?;

    let finish_raw = read_frame(s).await?;
    if Sha512::digest(&finish_raw).as_slice() != commitment {
        bail!("client finish does not match its commitment");
    }
    let msg = Ukey2Message::decode(&*finish_raw)?;
    if msg.message_type() != ukey2_message::Type::ClientFinish {
        bail!("expected ClientFinish, got {:?}", msg.message_type());
    }
    let finished = Ukey2ClientFinished::decode(msg.message_data())?;
    let peer = decode_public_key(finished.public_key())?;
    derive(&secret, &peer, &client_init_raw, &server_init, Role::Server)
}

async fn alert<S: AsyncWrite + Unpin, T>(s: &mut S, t: AlertType) -> anyhow::Result<T> {
    let msg = Ukey2Message {
        message_type: Some(ukey2_message::Type::Alert.into()),
        message_data: Some(Ukey2Alert { r#type: Some(t.into()), error_message: None }.encode_to_vec()),
    };
    let _ = write_frame(s, &msg.encode_to_vec()).await;
    bail!("UKEY2 handshake failed: {t:?}")
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

fn derive(
    secret: &SecretKey,
    peer: &PublicKey,
    client_init: &[u8],
    server_init: &[u8],
    role: Role,
) -> anyhow::Result<Keys> {
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let ikm = Sha256::digest(shared.raw_secret_bytes());
    let info = [client_init, server_init].concat();
    let auth = hkdf32(b"UKEY2 v1 auth", &ikm, &info);
    let next = hkdf32(b"UKEY2 v1 next", &ikm, &info);

    // D2D: per-role secrets, then SecureMessage encryption and signing keys.
    let d2d_salt = Sha256::digest(b"D2D");
    let sm_salt = Sha256::digest(b"SecureMessage");
    let direction = |label: &[u8]| {
        let base = hkdf32(&d2d_salt, &next, label);
        DirectionKeys { aes: hkdf32(&sm_salt, &base, b"ENC:2"), hmac: hkdf32(&sm_salt, &base, b"SIG:1") }
    };
    let (client, server) = (direction(b"client"), direction(b"server"));
    let (send, recv) = match role {
        Role::Client => (client, server),
        Role::Server => (server, client),
    };
    Ok(Keys { send, recv, auth })
}

/// Coordinates are encoded as two's-complement big-endian integers.
fn encode_coordinate(c: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    if c[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(c);
    v
}

fn decode_coordinate(c: &[u8]) -> anyhow::Result<[u8; 32]> {
    let start = c.iter().position(|&b| b != 0).unwrap_or(c.len());
    let c = &c[start..];
    if c.len() > 32 {
        bail!("coordinate too long");
    }
    let mut out = [0u8; 32];
    out[32 - c.len()..].copy_from_slice(c);
    Ok(out)
}

fn encode_public_key(key: &PublicKey) -> Vec<u8> {
    let p = key.to_encoded_point(false);
    GenericPublicKey {
        r#type: PublicKeyType::EcP256.into(),
        ec_p256_public_key: Some(EcP256PublicKey {
            x: encode_coordinate(p.x().expect("uncompressed point")),
            y: encode_coordinate(p.y().expect("uncompressed point")),
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

fn decode_public_key(raw: &[u8]) -> anyhow::Result<PublicKey> {
    let k = GenericPublicKey::decode(raw)?;
    let ec = k.ec_p256_public_key.context("not an EC P-256 key")?;
    let point = EncodedPoint::from_affine_coordinates(
        &decode_coordinate(&ec.x)?.into(),
        &decode_coordinate(&ec.y)?.into(),
        false,
    );
    Option::from(PublicKey::from_encoded_point(&point)).context("point is not on the curve")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salts_match_published_constants() {
        assert_eq!(
            Sha256::digest(b"D2D").to_vec(),
            hex("82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510")
        );
        assert_eq!(
            Sha256::digest(b"SecureMessage").to_vec(),
            hex("BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E")
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn public_key_roundtrip() {
        for _ in 0..64 {
            let k = SecretKey::random(&mut OsRng).public_key();
            assert_eq!(decode_public_key(&encode_public_key(&k)).unwrap(), k);
        }
    }

    #[tokio::test]
    async fn handshake_agrees() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (c, s) = tokio::join!(client(&mut a), server(&mut b));
        let (c, s) = (c.unwrap(), s.unwrap());
        assert_eq!(c.auth, s.auth);
        assert_eq!(c.pin(), s.pin());
        assert_eq!(c.send.aes, s.recv.aes);
        assert_eq!(c.send.hmac, s.recv.hmac);
        assert_eq!(c.recv.aes, s.send.aes);
        assert_ne!(c.send.aes, c.recv.aes);
    }
}
