use thiserror::Error;

pub const MAX_MESSAGE: usize = u16::MAX as usize;
pub const MAX_DATA: usize = 60 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub stream: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("frame too large")]
    Oversize,
    #[error("invalid frame")]
    Invalid,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if (self.kind == 3 && self.body.len() > MAX_DATA) || self.body.len() + 5 > MAX_MESSAGE {
            return Err(WireError::Oversize);
        }
        let mut out = Vec::with_capacity(self.body.len() + 5);
        out.push(self.kind);
        out.extend_from_slice(&self.stream.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 5 {
            return Err(WireError::Invalid);
        }
        if bytes.len() > MAX_MESSAGE {
            return Err(WireError::Oversize);
        }
        let kind = bytes[0];
        let body = &bytes[5..];
        if kind == 3 && body.len() > MAX_DATA {
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
            kind: 3,
            stream: 9,
            body: vec![1, 2],
        };
        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }

    #[test]
    fn rejects_oversize_data_frames_on_encode_and_decode() {
        let frame = Frame {
            kind: 3,
            stream: 0,
            body: vec![0; MAX_DATA + 1],
        };
        assert!(matches!(frame.encode(), Err(WireError::Oversize)));
        let mut bytes = vec![3, 0, 0, 0, 0];
        bytes.extend(vec![0; MAX_DATA + 1]);
        assert!(matches!(Frame::decode(&bytes), Err(WireError::Oversize)));
    }

    #[test]
    fn rejects_frames_larger_than_the_websocket_message_limit() {
        let mut bytes = vec![6, 0, 0, 0, 0];
        bytes.extend(vec![0; MAX_MESSAGE - 4]);
        assert!(matches!(Frame::decode(&bytes), Err(WireError::Oversize)));
    }

    #[test]
    fn allows_non_data_control_bodies_above_the_data_limit() {
        let frame = Frame {
            kind: 7,
            stream: 0,
            body: vec![0; MAX_DATA + 1],
        };
        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }
}
