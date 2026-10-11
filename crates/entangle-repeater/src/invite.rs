use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub repeater_public_key: [u8; 32],
    pub secret: [u8; 32],
    pub url: String,
}

#[derive(Debug, Error)]
pub enum InviteError {
    #[error("invalid invite code")]
    Invalid,
    #[error("invite URL is too long")]
    UrlTooLong,
}

pub fn encode(invite: &Invite) -> Result<String, InviteError> {
    let url = invite.url.as_bytes();
    let len = u16::try_from(url.len()).map_err(|_| InviteError::UrlTooLong)?;
    let mut bytes = Vec::with_capacity(67 + url.len());
    bytes.push(1);
    bytes.extend_from_slice(&invite.repeater_public_key);
    bytes.extend_from_slice(&invite.secret);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(url);
    let encoded = BASE32_NOPAD.encode(&bytes);
    let groups = encoded
        .as_bytes()
        .chunks(4)
        .map(|v| std::str::from_utf8(v).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    Ok(format!("ENTR1-{groups}"))
}

pub fn decode(code: &str) -> Result<Invite, InviteError> {
    let body = code.strip_prefix("ENTR1-").ok_or(InviteError::Invalid)?;
    let encoded = body
        .chars()
        .filter(|character| *character != '-' && !character.is_ascii_whitespace())
        .collect::<String>();
    let bytes = BASE32_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| InviteError::Invalid)?;
    if bytes.len() < 67 || bytes[0] != 1 {
        return Err(InviteError::Invalid);
    }
    let url_len = u16::from_be_bytes([bytes[65], bytes[66]]) as usize;
    if bytes.len() != 67 + url_len {
        return Err(InviteError::Invalid);
    }
    Ok(Invite {
        repeater_public_key: bytes[1..33].try_into().unwrap(),
        secret: bytes[33..65].try_into().unwrap(),
        url: String::from_utf8(bytes[67..].to_vec()).map_err(|_| InviteError::Invalid)?,
    })
}

pub fn secret_hash(secret: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invite_roundtrip() {
        let i = Invite {
            repeater_public_key: [1; 32],
            secret: [2; 32],
            url: "ws://127.0.0.1:1/entangle".into(),
        };
        let code = encode(&i).unwrap();
        assert!(code.starts_with("ENTR1-"));
        assert_eq!(decode(&code).unwrap(), i);
        assert!(decode(&code.replacen("ENTR1-", "ENTR1", 1)).is_err());
    }
}
