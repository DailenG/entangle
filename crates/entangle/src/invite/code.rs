use rand::RngCore;
use std::fmt;
use thiserror::Error;

pub const WORDS: [&str; 256] = [
    "quark", "muon", "photon", "boson", "pulsar", "nebula", "comet", "orbit", "nova", "quasar",
    "galaxy", "cosmic", "solar", "lunar", "stellar", "meteor", "asteroid", "planet", "saturn",
    "jupiter", "mars", "venus", "earth", "pluto", "ceres", "titan", "europa", "callisto", "triton",
    "charon", "vesta", "pallas", "hygiea", "eclipse", "aurora", "zenith", "nadir", "cluster",
    "crater", "corona", "magnetar", "neutrino", "proton", "neutron", "electron", "positron",
    "isotope", "plasma", "fusion", "fission", "gravity", "tensor", "vector", "scalar", "quanta",
    "string", "gluon", "lepton", "hadron", "meson", "spin", "energy", "force", "wave", "field",
    "vacuum", "laser", "optics", "lens", "prism", "mirror", "spectrum", "radio", "gamma", "alpha",
    "beta", "delta", "lambda", "omega", "sigma", "theta", "kappa", "zeta", "epsilon", "flux",
    "phase", "quartz", "crystal", "silicon", "carbon", "copper", "iron", "nickel", "cobalt",
    "mercury", "helium", "argon", "oxygen", "nitrogen", "radon", "molecule", "element", "matter",
    "mass", "charge", "current", "voltage", "circuit", "resistor", "amber", "inductor", "diode",
    "switch", "battery", "cable", "signal", "anchor", "basket", "beacon", "birch", "blanket",
    "bottle", "bridge", "bucket", "candle", "canyon", "carpet", "castle", "cedar", "chain",
    "cherry", "chimney", "circle", "clover", "cobble", "coffee", "compass", "coral", "cotton",
    "cradle", "daisy", "desert", "diamond", "dinner", "dolphin", "dragon", "drawer", "drum",
    "eagle", "engine", "fabric", "falcon", "feather", "fence", "finger", "flower", "forest",
    "fossil", "fountain", "garden", "garlic", "guitar", "hammer", "harbor", "hazel", "helmet",
    "honey", "island", "jacket", "jigsaw", "jungle", "kernel", "ladder", "lantern", "lemon",
    "marble", "meadow", "melon", "needle", "napkin", "ocean", "olive", "orange", "orchid",
    "paddle", "parrot", "pebble", "pepper", "pillow", "pocket", "pumpkin", "rabbit", "ribbon",
    "rocket", "saddle", "sailor", "salmon", "sandal", "sapphire", "shadow", "shingle", "silver",
    "singer", "socket", "spider", "spoon", "stable", "statue", "stream", "sugar", "sunset",
    "table", "temple", "thunder", "timber", "tomato", "tunnel", "valley", "velvet", "violet",
    "wallet", "walnut", "window", "winter", "wooden", "yonder", "yellow", "zephyr", "anode",
    "aperture", "baryon", "cavity", "diffuse", "dipole", "entropy", "fermi", "horizon", "inertia",
    "isobar", "kepler", "kinetic", "lattice", "lumen", "mantle", "axion", "tachyon", "higgs",
    "redshift", "penumbra", "umbra", "tidal", "star", "flare", "auric", "plumb", "qubit",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteCode {
    pub nameplate: u8,
    words: [u8; 3],
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodeError {
    #[error("invite code must contain a nameplate and three words")]
    InvalidFormat,
    #[error("invite nameplate must be between 1 and 99")]
    InvalidNameplate,
    #[error("unknown invite word: {0}")]
    UnknownWord(String),
}

impl InviteCode {
    pub fn generate(nameplate: u8) -> Self {
        assert!((1..=99).contains(&nameplate));
        let mut words = [0; 3];
        rand::rngs::OsRng.fill_bytes(&mut words);
        Self { nameplate, words }
    }

    pub fn parse(value: &str) -> Result<Self, CodeError> {
        let normalized = value.trim().to_ascii_lowercase();
        let parts = normalized
            .split(|character: char| character == '-' || character.is_whitespace())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if parts.len() != 4 {
            return Err(CodeError::InvalidFormat);
        }
        if !parts[0].bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CodeError::InvalidNameplate);
        }
        let nameplate = parts[0]
            .parse::<u8>()
            .ok()
            .filter(|number| (1..=99).contains(number))
            .ok_or(CodeError::InvalidNameplate)?;
        let mut words = [0; 3];
        for (slot, part) in words.iter_mut().zip(&parts[1..]) {
            *slot = WORDS
                .iter()
                .position(|word| word == part)
                .ok_or_else(|| CodeError::UnknownWord((*part).to_owned()))?
                as u8;
        }
        Ok(Self { nameplate, words })
    }
}

impl fmt::Display for InviteCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{}-{}-{}",
            self.nameplate,
            WORDS[usize::from(self.words[0])],
            WORDS[usize::from(self.words[1])],
            WORDS[usize::from(self.words[2])]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn word_list_has_unique_entries_without_prefix_pairs() {
        assert_eq!(WORDS.len(), 256);
        assert_eq!(WORDS.iter().collect::<HashSet<_>>().len(), WORDS.len());
        for word in WORDS {
            assert!((3..=8).contains(&word.len()));
            assert!(word.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(WORDS
                .iter()
                .all(|other| word == *other || !other.starts_with(word)));
        }
    }

    #[test]
    fn generated_code_roundtrips() {
        let code = InviteCode::generate(7);
        assert_eq!(InviteCode::parse(&code.to_string()).unwrap(), code);
    }

    #[test]
    fn parser_normalizes_separators_and_case() {
        assert_eq!(
            InviteCode::parse(" 7 Amber  photon-QUASAR ")
                .unwrap()
                .to_string(),
            "7-amber-photon-quasar"
        );
    }

    #[test]
    fn parser_rejects_unknown_words_and_invalid_nameplates() {
        assert!(matches!(
            InviteCode::parse("7-amber-photon-unknown"),
            Err(CodeError::UnknownWord(_))
        ));
        assert_eq!(
            InviteCode::parse("0-amber-photon-quasar"),
            Err(CodeError::InvalidNameplate)
        );
        assert_eq!(
            InviteCode::parse("100-amber-photon-quasar"),
            Err(CodeError::InvalidNameplate)
        );
    }
}
