use crate::error::Argon2Error;
use crate::hasher::{Algorithm, MAX_HASH_B64_LEN, MAX_SALT_B64_LEN};

use std::str::FromStr;

pub struct TokenizedHash {
    pub v: u32,
    pub alg: Algorithm,
    pub mem_cost_kib: u32,
    pub iterations: u32,
    pub threads: u32,
    pub b64_salt: String,
    pub b64_hash: String,
}

impl FromStr for TokenizedHash {
    type Err = Argon2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        enum HashStates {
            Start,
            HashTypeStart,
            HashTypeA,
            HashTypeAr,
            HashTypeArg,
            HashTypeArgo,
            HashTypeArgon,
            HashTypeArgon2,
            HashTypeArgon2d,
            HashTypeArgon2i,
            HashTypeArgon2id,
            HashTypeComplete,
            VKey,
            VEquals,
            VValue,
            VComplete,
            MKey,
            MEquals,
            MValue,
            MComplete,
            TKey,
            TEquals,
            TValue,
            TComplete,
            PKey,
            PEquals,
            PValue,
            PComplete,
            Salt,
            HashStart,
            Hash,
        }

        let mut state = HashStates::Start;

        let mut has_m = false;
        let mut has_t = false;
        let mut has_p = false;

        let mut v = 0..0;
        let mut m = 0..0;
        let mut t = 0..0;
        let mut p = 0..0;

        let mut salt = String::with_capacity(22); // 16 bytes, base64-encoded (no padding)
        let mut hash = String::new();

        let mut alg = Algorithm::Argon2id;

        for (i, c) in s.char_indices() {
            match state {
                HashStates::Start => {
                    state = match c {
                        '$' => HashStates::HashTypeStart,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeStart => {
                    state = match c {
                        'a' => HashStates::HashTypeA,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeA => {
                    state = match c {
                        'r' => HashStates::HashTypeAr,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeAr => {
                    state = match c {
                        'g' => HashStates::HashTypeArg,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArg => {
                    state = match c {
                        'o' => HashStates::HashTypeArgo,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgo => {
                    state = match c {
                        'n' => HashStates::HashTypeArgon,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon => {
                    state = match c {
                        '2' => HashStates::HashTypeArgon2,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2 => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2d,
                        'i' => HashStates::HashTypeArgon2i,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2d => {
                    state = match c {
                        '$' => {
                            alg = Algorithm::Argon2d;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Missing '$' delimiter")),
                    };
                }

                HashStates::HashTypeArgon2i => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2id,
                        '$' => {
                            alg = Algorithm::Argon2i;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2id => {
                    state = match c {
                        '$' => {
                            alg = Algorithm::Argon2id;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Missing '$' delimiter")),
                    };
                }

                HashStates::HashTypeComplete => {
                    state = match c {
                        'v' => HashStates::VKey,
                        _ => return Err(Argon2Error::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VKey => {
                    state = match c {
                        '=' => HashStates::VEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VEquals => {
                    if !c.is_ascii_digit() {
                        return Err(Argon2Error::InvalidHash("Invalid version"));
                    }
                    v = i..(i + 1);
                    state = HashStates::VValue;
                }

                HashStates::VValue => {
                    if c == '$' {
                        state = HashStates::VComplete;
                    } else {
                        if !c.is_ascii_digit() {
                            return Err(Argon2Error::InvalidHash("Invalid version"));
                        }
                        v.end += 1;
                    }
                }

                HashStates::VComplete => {
                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::MKey => {
                    if has_m {
                        return Err(Argon2Error::InvalidHash("Duplicate key 'm'"));
                    }

                    state = match c {
                        '=' => HashStates::MEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 'm' parameter")),
                    }
                }

                HashStates::MEquals => {
                    if !c.is_ascii_digit() {
                        return Err(Argon2Error::InvalidHash("Invalid m"));
                    }
                    m = i..(i + 1);
                    state = HashStates::MValue;
                }

                HashStates::MValue => {
                    if c == ',' {
                        state = HashStates::MComplete;
                    } else if c == '$' && has_t && has_p {
                        state = HashStates::Salt;
                    } else {
                        if !c.is_ascii_digit() {
                            return Err(Argon2Error::InvalidHash("Invalid m"));
                        }
                        m.end += 1;
                    }
                }

                HashStates::MComplete => {
                    has_m = true;

                    state = match c {
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::TKey => {
                    if has_t {
                        return Err(Argon2Error::InvalidHash("Duplicate key 't'"));
                    }

                    state = match c {
                        '=' => HashStates::TEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 't' paramter")),
                    }
                }

                HashStates::TEquals => {
                    if !c.is_ascii_digit() {
                        return Err(Argon2Error::InvalidHash("Invalid t"));
                    }
                    t = i..(i + 1);
                    state = HashStates::TValue;
                }

                HashStates::TValue => {
                    if c == ',' {
                        state = HashStates::TComplete;
                    } else if c == '$' && has_m && has_p {
                        state = HashStates::Salt;
                    } else {
                        if !c.is_ascii_digit() {
                            return Err(Argon2Error::InvalidHash("Invalid t"));
                        }
                        t.end += 1;
                    }
                }

                HashStates::TComplete => {
                    has_t = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing paramter",
                            ))
                        }
                    }
                }

                HashStates::PKey => {
                    if has_p {
                        return Err(Argon2Error::InvalidHash("Duplicate key 'p'"));
                    }

                    state = match c {
                        '=' => HashStates::PEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 'p' paramter")),
                    }
                }

                HashStates::PEquals => {
                    if !c.is_ascii_digit() {
                        return Err(Argon2Error::InvalidHash("Invalid p"));
                    }
                    p = i..(i + 1);
                    state = HashStates::PValue;
                }

                HashStates::PValue => {
                    if c == ',' {
                        state = HashStates::PComplete;
                    } else if c == '$' && has_m && has_t {
                        state = HashStates::Salt;
                    } else {
                        if !c.is_ascii_digit() {
                            return Err(Argon2Error::InvalidHash("Invalid p"));
                        }
                        p.end += 1;
                    }
                }

                HashStates::PComplete => {
                    has_p = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::Salt => {
                    if c == '$' {
                        state = HashStates::HashStart;
                    } else {
                        if salt.len() + c.len_utf8() > MAX_SALT_B64_LEN {
                            return Err(Argon2Error::InvalidHash("Salt is too long"));
                        }
                        salt.push(c);
                    }
                }

                HashStates::HashStart => {
                    if c == '$' {
                        return Err(Argon2Error::InvalidHash("Missing hash after salt"));
                    }

                    if s.len() - i > MAX_HASH_B64_LEN {
                        return Err(Argon2Error::InvalidHash("Hash is too long"));
                    }
                    hash = String::from(&s[i..]);
                    state = HashStates::Hash;

                    break;
                }

                // Should break out of loop before this point
                HashStates::Hash => unreachable!(),
            }
        }

        if !matches!(state, HashStates::Hash) {
            return Err(Argon2Error::InvalidHash("Hash is incomplete"));
        }

        salt.shrink_to_fit();

        let v: u32 = s[v]
            .parse()
            .map_err(|_| Argon2Error::InvalidHash("Invalid version"))?;

        let mem_cost_kib: u32 = s[m]
            .parse()
            .map_err(|_| Argon2Error::InvalidHash("Invalid m"))?;

        let iterations: u32 = s[t]
            .parse()
            .map_err(|_| Argon2Error::InvalidHash("Invalid t"))?;

        let threads: u32 = s[p]
            .parse()
            .map_err(|_| Argon2Error::InvalidHash("Invalid p"))?;

        Ok(Self {
            v,
            alg,
            mem_cost_kib,
            iterations,
            threads,
            b64_salt: salt,
            b64_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ascii_numeric_fields_without_panicking() {
        for (field, error) in [
            ("v", "Invalid version"),
            ("m", "Invalid m"),
            ("t", "Invalid t"),
            ("p", "Invalid p"),
        ] {
            for value in ["é", "1é", "💥", "1💥", "+1", ""] {
                let params = "v=19$m=128,t=3,p=2".replace(
                    match field {
                        "v" => "v=19",
                        "m" => "m=128",
                        "t" => "t=3",
                        _ => "p=2",
                    },
                    &format!("{field}={value}"),
                );
                let input = format!("$argon2id${params}$AQIDBAUGBwg$AQIDBAUGBwg");
                assert!(
                    matches!(TokenizedHash::from_str(&input), Err(Argon2Error::InvalidHash(msg)) if msg == error),
                    "{input}"
                );
            }
        }
    }

    #[test]
    fn rejects_oversized_salt_before_reaching_the_hash() {
        // No final delimiter: rejection must occur while reading the salt.
        let input = format!(
            "$argon2id$v=19$m=128,t=3,p=2${}",
            "A".repeat(MAX_SALT_B64_LEN + 1)
        );
        assert!(matches!(
            TokenizedHash::from_str(&input),
            Err(Argon2Error::InvalidHash("Salt is too long"))
        ));
    }

    #[test]
    fn rejects_oversized_hash_during_tokenization() {
        let input = format!(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg${}",
            "A".repeat(MAX_HASH_B64_LEN + 1)
        );
        assert!(matches!(
            TokenizedHash::from_str(&input),
            Err(Argon2Error::InvalidHash("Hash is too long"))
        ));
    }
}
