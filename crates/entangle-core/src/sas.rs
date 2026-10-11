//! Versioned short authentication strings for human peer approval.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the immutable emoji table used to derive SAS values.
pub const SAS_TABLE_VERSION: u32 = 1;

/// Fixed 6-bit emoji table. Its order is part of the wire protocol.
pub const EMOJI: [(&str, &str); 64] = [
    ("🚀", "rocket"),
    ("🌙", "moon"),
    ("⭐", "star"),
    ("🌍", "globe"),
    ("⚡", "lightning"),
    ("🌈", "rainbow"),
    ("🔥", "fire"),
    ("💧", "droplet"),
    ("🌋", "volcano"),
    ("🌊", "wave"),
    ("⛄", "snowman"),
    ("🔭", "telescope"),
    ("💡", "bulb"),
    ("🔋", "battery"),
    ("🧲", "magnet"),
    ("🌵", "cactus"),
    ("🌲", "tree"),
    ("🍄", "mushroom"),
    ("🌻", "sunflower"),
    ("🍀", "clover"),
    ("🌽", "corn"),
    ("🍎", "apple"),
    ("🍇", "grapes"),
    ("🥑", "avocado"),
    ("🥕", "carrot"),
    ("🍕", "pizza"),
    ("🎂", "cake"),
    ("🍩", "doughnut"),
    ("🍞", "bread"),
    ("🍿", "popcorn"),
    ("🐬", "dolphin"),
    ("🐙", "octopus"),
    ("🐢", "turtle"),
    ("🐘", "elephant"),
    ("🐍", "snake"),
    ("🐧", "penguin"),
    ("🦋", "butterfly"),
    ("🐌", "snail"),
    ("🦀", "crab"),
    ("🐎", "horse"),
    ("🐇", "rabbit"),
    ("🔑", "key"),
    ("⚓", "anchor"),
    ("🔔", "bell"),
    ("🏠", "house"),
    ("🎁", "gift"),
    ("🏆", "trophy"),
    ("⚽", "ball"),
    ("🎸", "guitar"),
    ("🎺", "trumpet"),
    ("🎹", "piano"),
    ("🎩", "hat"),
    ("⌛", "hourglass"),
    ("🔨", "hammer"),
    ("🎲", "dice"),
    ("📷", "camera"),
    ("🚲", "bicycle"),
    ("🚗", "car"),
    ("🚂", "train"),
    ("🚁", "helicopter"),
    ("⛵", "sailboat"),
    ("☔", "umbrella"),
    ("💎", "diamond"),
    ("🔮", "crystal"),
];

/// Three 6-bit indices into [`EMOJI`].
pub type Sas = [u8; 3];

/// The deterministic role used by commit-then-reveal verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The lower static public key commits to a nonce before receiving one.
    Committer,
    /// The higher static public key reveals a nonce after receiving the commitment.
    Revealer,
}

/// Returns each peer's role by lexicographically comparing its Noise static key.
///
/// Equal keys cannot establish distinct commit and reveal roles and are rejected.
pub fn role(local: &[u8; 32], remote: &[u8; 32]) -> Option<Role> {
    match local.cmp(remote) {
        std::cmp::Ordering::Less => Some(Role::Committer),
        std::cmp::Ordering::Greater => Some(Role::Revealer),
        std::cmp::Ordering::Equal => None,
    }
}

/// Commits to a committer nonce and the ordered public keys.
///
/// Binding both keys and withholding the nonce until the revealer nonce is
/// known prevents either peer from grinding a value against the final SAS.
pub fn commitment(nonce_c: &[u8; 32], key_c: &[u8; 32], key_r: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"entangle-sas-commit-v1");
    hasher.update(nonce_c);
    hasher.update(key_c);
    hasher.update(key_r);
    hasher.finalize().into()
}

/// Derives the three 6-bit SAS indices from the ordered keys and nonces.
pub fn derive(key_c: &[u8; 32], key_r: &[u8; 32], nonce_c: &[u8; 32], nonce_r: &[u8; 32]) -> Sas {
    let mut hasher = Sha256::new();
    hasher.update(b"entangle-sas-v1");
    hasher.update(SAS_TABLE_VERSION.to_be_bytes());
    hasher.update(key_c);
    hasher.update(key_r);
    hasher.update(nonce_c);
    hasher.update(nonce_r);
    let digest = hasher.finalize();
    [
        digest[0] >> 2,
        ((digest[0] & 0x03) << 4) | (digest[1] >> 4),
        ((digest[1] & 0x0f) << 2) | (digest[2] >> 6),
    ]
}

/// Renders a SAS as three emoji names with the protocol's fixed spacing.
pub fn render(sas: Sas) -> String {
    format!(
        "{} {}  {} {}  {} {}",
        EMOJI[sas[0] as usize].0,
        EMOJI[sas[0] as usize].1,
        EMOJI[sas[1] as usize].0,
        EMOJI[sas[1] as usize].1,
        EMOJI[sas[2] as usize].0,
        EMOJI[sas[2] as usize].1
    )
}

/// Generates three random SAS decoys, distinct from the real set at every position.
pub fn decoys<R: Rng + ?Sized>(real: Sas, rng: &mut R) -> [Sas; 3] {
    let mut decoys = [[0; 3]; 3];
    for position in 0..3 {
        for decoy_index in 0..3 {
            loop {
                let candidate = rng.gen_range(0..64);
                if candidate != real[position]
                    && decoys[..decoy_index]
                        .iter()
                        .all(|decoy| decoy[position] != candidate)
                {
                    decoys[decoy_index][position] = candidate;
                    break;
                }
            }
        }
    }
    decoys
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::collections::HashSet;

    #[test]
    fn emoji_table_is_unique_and_uses_single_scalar_lowercase_names() {
        let glyphs: HashSet<_> = EMOJI.iter().map(|(glyph, _)| *glyph).collect();
        let names: HashSet<_> = EMOJI.iter().map(|(_, name)| *name).collect();
        assert_eq!(EMOJI.len(), 64);
        assert_eq!(glyphs.len(), EMOJI.len());
        assert_eq!(names.len(), EMOJI.len());
        for (glyph, name) in EMOJI {
            assert_eq!(glyph.chars().count(), 1, "{glyph}");
            assert!(!name.is_empty());
            assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(!name.contains(' '));
        }
    }

    #[test]
    fn role_is_derived_from_ordered_static_keys() {
        assert_eq!(role(&[1; 32], &[2; 32]), Some(Role::Committer));
        assert_eq!(role(&[2; 32], &[1; 32]), Some(Role::Revealer));
        assert_eq!(role(&[1; 32], &[1; 32]), None);
    }

    #[test]
    fn commitment_matches_the_domain_separated_vector_and_rejects_mismatches() {
        let nonce = [3; 32];
        let key_c = [1; 32];
        let key_r = [2; 32];
        assert_eq!(
            hex::encode(commitment(&nonce, &key_c, &key_r)),
            "a3ba8430b30f20f762703bce7c05da202c0d70c4ca381aa3894426722d43deba"
        );
        assert_ne!(
            commitment(&nonce, &key_c, &key_r),
            commitment(&[4; 32], &key_c, &key_r)
        );
        assert_ne!(
            commitment(&nonce, &key_c, &key_r),
            commitment(&nonce, &key_r, &key_c)
        );
    }

    #[test]
    fn derive_is_deterministic_and_order_sensitive() {
        let key_c = [1; 32];
        let key_r = [2; 32];
        let nonce_c = [3; 32];
        let nonce_r = [4; 32];
        assert_eq!(derive(&key_c, &key_r, &nonce_c, &nonce_r), [12, 44, 39]);
        assert_ne!(
            derive(&key_c, &key_r, &nonce_c, &nonce_r),
            derive(&key_r, &key_c, &nonce_c, &nonce_r)
        );
        assert_ne!(
            derive(&key_c, &key_r, &nonce_c, &nonce_r),
            derive(&key_c, &key_r, &nonce_r, &nonce_c)
        );
    }

    #[test]
    fn digest_bit_extraction_uses_the_first_18_bits_big_endian() {
        let digest = [0xb6, 0x53, 0x80];
        assert_eq!(
            [
                digest[0] >> 2,
                ((digest[0] & 0x03) << 4) | (digest[1] >> 4),
                ((digest[1] & 0x0f) << 2) | (digest[2] >> 6),
            ],
            [45, 37, 14]
        );
    }

    #[test]
    fn decoys_differ_from_real_and_each_other_at_every_position() {
        let mut rng = OsRng;
        for _ in 0..10_000 {
            let mut bytes = [0; 3];
            rng.fill_bytes(&mut bytes);
            let real = bytes.map(|byte| byte & 0x3f);
            let decoys = decoys(real, &mut rng);
            for position in 0..3 {
                assert!(decoys.iter().all(|decoy| decoy[position] != real[position]));
                for first in 0..3 {
                    for second in first + 1..3 {
                        assert_ne!(decoys[first][position], decoys[second][position]);
                    }
                }
            }
        }
    }

    #[test]
    fn rendering_uses_the_fixed_two_space_separator() {
        assert_eq!(render([30, 0, 1]), "🐬 dolphin  🚀 rocket  🌙 moon");
    }
}
