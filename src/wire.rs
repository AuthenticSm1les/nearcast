//! Framing: every message is a 4-byte big-endian length followed by the bytes.
//! After UKEY2, each frame is a SecureMessage wrapping a DeviceToDeviceMessage
//! (AES-256-CBC + HMAC-SHA256, with per-direction sequence numbers).

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{bail, Context};
use hmac::{Hmac, Mac};
use prost::Message;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::connections::OfflineFrame;
use crate::proto::securegcm::{DeviceToDeviceMessage, GcmMetadata, Type as GcmType};
use crate::proto::securemessage::{EncScheme, Header, HeaderAndBody, SecureMessage, SigScheme};

/// Largest frame we accept (payload chunks are 512 KiB plus overhead).
pub const MAX_FRAME_LEN: usize = 5 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame too large ({len} bytes)");
    }
    let mut buf = vec![0; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(data.len()).context("frame too large")?;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Keys for one direction of the secure channel.
#[derive(Clone)]
pub struct DirectionKeys {
    pub aes: [u8; 32],
    pub hmac: [u8; 32],
}

/// Sending half of the secure channel.
pub struct SecureWriter<W> {
    inner: W,
    keys: DirectionKeys,
    seq: i32,
}

impl<W: AsyncWrite + Unpin> SecureWriter<W> {
    pub fn new(inner: W, keys: DirectionKeys) -> Self {
        Self { inner, keys, seq: 0 }
    }

    pub async fn send(&mut self, frame: &OfflineFrame) -> anyhow::Result<()> {
        self.seq = self.seq.checked_add(1).context("sequence number overflow")?;
        let d2d = DeviceToDeviceMessage {
            sequence_number: Some(self.seq),
            message: Some(frame.encode_to_vec()),
        };
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        let body = Aes256CbcEnc::new(&self.keys.aes.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&d2d.encode_to_vec());
        let header_and_body = HeaderAndBody {
            header: Header {
                signature_scheme: SigScheme::HmacSha256.into(),
                encryption_scheme: EncScheme::Aes256Cbc.into(),
                iv: Some(iv.to_vec()),
                public_metadata: Some(
                    GcmMetadata {
                        r#type: GcmType::DeviceToDeviceMessage.into(),
                        version: Some(1),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
            body,
        }
        .encode_to_vec();
        let mut mac = HmacSha256::new_from_slice(&self.keys.hmac)?;
        mac.update(&header_and_body);
        let msg = SecureMessage {
            header_and_body,
            signature: mac.finalize().into_bytes().to_vec(),
        };
        write_frame(&mut self.inner, &msg.encode_to_vec()).await
    }

    /// Sends a frame outside the secure channel, without using a sequence
    /// number.
    pub async fn send_plain(&mut self, frame: &OfflineFrame) -> anyhow::Result<()> {
        write_frame(&mut self.inner, &frame.encode_to_vec()).await
    }

    /// Moves to another stream, keeping the keys and sequence numbers.
    pub fn replace(&mut self, inner: W) -> W {
        std::mem::replace(&mut self.inner, inner)
    }

    pub async fn shutdown(&mut self) {
        let _ = self.inner.shutdown().await;
    }
}

/// Receiving half of the secure channel.
pub struct SecureReader<R> {
    inner: R,
    keys: DirectionKeys,
    seq: i32,
}

impl<R: AsyncRead + Unpin> SecureReader<R> {
    pub fn new(inner: R, keys: DirectionKeys) -> Self {
        Self { inner, keys, seq: 0 }
    }

    /// Moves to another stream, keeping the keys and sequence numbers.
    pub fn replace(&mut self, inner: R) -> R {
        std::mem::replace(&mut self.inner, inner)
    }

    pub async fn recv(&mut self) -> anyhow::Result<OfflineFrame> {
        let raw = read_frame(&mut self.inner).await?;
        let msg = SecureMessage::decode(&*raw).context("decoding SecureMessage")?;
        let mut mac = HmacSha256::new_from_slice(&self.keys.hmac)?;
        mac.update(&msg.header_and_body);
        mac.verify_slice(&msg.signature).context("bad message signature")?;

        let hb = HeaderAndBody::decode(&*msg.header_and_body)?;
        if hb.header.encryption_scheme() != EncScheme::Aes256Cbc {
            bail!("unexpected encryption scheme");
        }
        let iv: [u8; 16] = hb.header.iv().try_into().context("bad IV length")?;
        let plain = Aes256CbcDec::new(&self.keys.aes.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&hb.body)
            .map_err(|_| anyhow::anyhow!("bad padding"))?;
        let d2d = DeviceToDeviceMessage::decode(&*plain)?;

        self.seq = self.seq.checked_add(1).context("sequence number overflow")?;
        if d2d.sequence_number() != self.seq {
            bail!("unexpected sequence number {} (wanted {})", d2d.sequence_number(), self.seq);
        }
        Ok(OfflineFrame::decode(d2d.message())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::connections::{v1_frame, KeepAliveFrame, V1Frame};

    #[tokio::test]
    async fn secure_roundtrip_and_tamper() {
        let keys = DirectionKeys { aes: [7; 32], hmac: [9; 32] };
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut w = SecureWriter::new(a, keys.clone());
        let mut r = SecureReader::new(b, keys);
        let frame = OfflineFrame {
            version: Some(1),
            v1: Some(V1Frame {
                r#type: Some(v1_frame::FrameType::KeepAlive.into()),
                keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                ..Default::default()
            }),
        };
        w.send(&frame).await.unwrap();
        w.send(&frame).await.unwrap();
        assert_eq!(r.recv().await.unwrap(), frame);
        assert_eq!(r.recv().await.unwrap(), frame);

        // A wrong key must fail verification.
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut w = SecureWriter::new(a, DirectionKeys { aes: [7; 32], hmac: [1; 32] });
        let mut r = SecureReader::new(b, DirectionKeys { aes: [7; 32], hmac: [9; 32] });
        w.send(&frame).await.unwrap();
        assert!(r.recv().await.is_err());
    }
}
