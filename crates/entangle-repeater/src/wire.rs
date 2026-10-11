//! Frame codec and size limits for the repeater's encrypted session protocol.

use thiserror::Error;

/// WebSocket message size limit for Noise ciphertext, including its tag.
pub const MAX_MESSAGE: usize = u16::MAX as usize;
/// Maximum plaintext accepted by Noise before its 16-byte authentication tag.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - 16;
/// Maximum DATA body size, independent of frame and Noise headers.
pub const MAX_DATA: usize = 60 * 1024;
/// OPEN frame kind.
pub const OPEN: u8 = 0x01;
/// INCOMING frame kind.
pub const INCOMING: u8 = 0x02;
/// DATA frame kind.
pub const DATA: u8 = 0x03;
/// CLOSE frame kind.
pub const CLOSE: u8 = 0x04;
/// OPEN_FAIL frame kind.
pub const OPEN_FAIL: u8 = 0x05;
/// LIST frame kind.
pub const LIST: u8 = 0x06;
/// LIST_REPLY frame kind.
pub const LIST_REPLY: u8 = 0x07;
/// PING frame kind.
pub const PING: u8 = 0x08;
/// PONG frame kind.
pub const PONG: u8 = 0x09;
/// High bit reserved for repeater-assigned incoming stream identifiers.
pub const INCOMING_BIT: u32 = 0x8000_0000;
/// Stream identifier used for session-level control frames.
pub const SESSION_STREAM: u32 = 0;

/// Decoded repeater frame: kind, big-endian stream ID, and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Numeric frame kind.
    pub kind: u8,
    /// Stream identifier, or [`SESSION_STREAM`] for session control.
    pub stream: u32,
    /// Frame payload, excluding the five-byte header.
    pub body: Vec<u8>,
}

/// Wire-frame validation failures.
#[derive(Debug, Error)]
pub enum WireError {
    /// Frame exceeds DATA, plaintext, or ciphertext limits.
    #[error("frame too large")]
    Oversize,
    /// Frame is shorter than its required header.
    #[error("invalid frame")]
    Invalid,
}

impl Frame {
    /// Encodes a plaintext Noise payload as `kind:u8 | stream:u32 BE | body`.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let size = self.body.len() + 5;
        if (self.kind == DATA && self.body.len() > MAX_DATA) || size > MAX_PLAINTEXT {
            return Err(WireError::Oversize);
        }
        let mut out = Vec::with_capacity(size);
        out.push(self.kind);
        out.extend_from_slice(&self.stream.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    /// Decodes and validates a plaintext Noise payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 5 {
            return Err(WireError::Invalid);
        }
        if bytes.len() > MAX_PLAINTEXT {
            return Err(WireError::Oversize);
        }
        let kind = bytes[0];
        let body = &bytes[5..];
        if kind == DATA && body.len() > MAX_DATA {
            return Err(WireError::Oversize);
        }
        Ok(Self {
            kind,
            stream: u32::from_be_bytes(bytes[1..5].try_into().unwrap()),
            body: body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame {
            kind: DATA,
            stream: 9,
            body: vec![1, 2],
        };
        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }

    #[test]
    fn rejects_oversize_data_frames_on_encode_and_decode() {
        let frame = Frame {
            kind: DATA,
            stream: SESSION_STREAM,
            body: vec![0; MAX_DATA + 1],
        };
        assert!(matches!(frame.encode(), Err(WireError::Oversize)));
        let mut bytes = vec![DATA, 0, 0, 0, 0];
        bytes.extend(vec![0; MAX_DATA + 1]);
        assert!(matches!(Frame::decode(&bytes), Err(WireError::Oversize)));
    }

    #[test]
    fn rejects_plaintext_larger_than_noise_capacity() {
        let frame = Frame {
            kind: LIST_REPLY,
            stream: SESSION_STREAM,
            body: vec![0; MAX_PLAINTEXT - 4],
        };
        assert!(matches!(frame.encode(), Err(WireError::Oversize)));

        let mut bytes = vec![LIST_REPLY, 0, 0, 0, 0];
        bytes.extend(vec![0; MAX_PLAINTEXT - 4]);
        assert!(matches!(Frame::decode(&bytes), Err(WireError::Oversize)));
    }

    #[test]
    fn allows_non_data_control_bodies_above_the_data_limit() {
        let frame = Frame {
            kind: LIST_REPLY,
            stream: SESSION_STREAM,
            body: vec![0; MAX_DATA + 1],
        };
        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }

    #[test]
    fn accepts_maximum_noise_plaintext() {
        let frame = Frame {
            kind: LIST_REPLY,
            stream: SESSION_STREAM,
            body: vec![0; MAX_PLAINTEXT - 5],
        };
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded.len(), MAX_PLAINTEXT);
        assert_eq!(Frame::decode(&encoded).unwrap(), frame);
    }
}
