//! Bech32, hand-rolled.
//!
//! The `bech32` crate enforces the BIP-0173 90-character code limit. age applies
//! no length limit, and an `age1pq1…` recipient is about 1960 characters, so the
//! crate cannot encode one. Rather than fight it with a custom `Checksum` impl,
//! this is the same ~80 lines the Kotlin and Swift cores already carry.
//!
//! BIP-0173 checksum (constant 1), no length cap, case-insensitive decode.

use crate::error::{CoreError, Result};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Map a 5-bit value to its charset character. Total by construction: the mask
/// puts every input in range, so there is no panicking path to reason about.
#[expect(
    clippy::indexing_slicing,
    reason = "the mask guarantees an index below 32"
)]
fn charset_char(five_bits: u8) -> char {
    char::from(CHARSET[usize::from(five_bits & 31)])
}

/// Generous sanity cap. Not part of the spec; it just stops a hostile string
/// from making us allocate without bound. An `age1pq1…` key needs ~1960.
const MAX_LEN: usize = 8192;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    out.extend(bytes.iter().map(|c| c >> 5));
    out.push(0);
    out.extend(bytes.iter().map(|c| c & 31));
    out
}

/// Regroup `data` from `from` bits per element to `to` bits per element.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    let maxv: u32 = (1 << to) - 1;

    for &value in data {
        let v = u32::from(value);
        if (v >> from) != 0 {
            return None;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }

    Some(out)
}

/// Encode `data` under `hrp`. The HRP is lowercased for checksum purposes, as
/// the spec requires; callers wanting age's uppercase identity form should
/// uppercase the whole result.
///
/// # Errors
///
/// [`CoreError::InvalidRecipient`] if the HRP is empty or out of range.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
    let lower = hrp.to_lowercase();
    if lower.is_empty() || !lower.bytes().all(|c| (33..=126).contains(&c)) {
        return Err(CoreError::InvalidRecipient(format!(
            "bad bech32 hrp: {hrp}"
        )));
    }

    let five = convert_bits(data, 8, 5, true)
        .ok_or_else(|| CoreError::InvalidRecipient("bech32 regroup failed".to_owned()))?;

    let mut checksum_input = hrp_expand(&lower);
    checksum_input.extend_from_slice(&five);
    checksum_input.extend_from_slice(&[0; 6]);
    let polymod = polymod(&checksum_input) ^ 1;

    let mut out = String::with_capacity(lower.len() + 1 + five.len() + 6);
    out.push_str(&lower);
    out.push('1');
    for v in five {
        out.push(charset_char(v));
    }
    for i in 0..6 {
        out.push(charset_char(((polymod >> (5 * (5 - i))) & 31) as u8));
    }
    Ok(out)
}

/// Decode a Bech32 string into its HRP (lowercased) and payload bytes.
///
/// # Errors
///
/// [`CoreError::InvalidRecipient`] for mixed case, a bad character, a missing
/// separator, or a failed checksum.
pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
    let bad = |why: &str| CoreError::InvalidRecipient(format!("bech32: {why}"));

    if s.len() > MAX_LEN {
        return Err(bad("string is implausibly long"));
    }
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(bad("mixed case"));
    }
    let s = s.to_lowercase();

    let sep = s.rfind('1').ok_or_else(|| bad("no separator"))?;
    if sep == 0 || sep + 7 > s.len() {
        return Err(bad("separator in the wrong place"));
    }
    let (hrp, rest) = s.split_at(sep);
    let data_part = &rest[1..];

    let mut five = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        let idx = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| bad("character outside the charset"))?;
        five.push(idx as u8);
    }

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&five);
    if polymod(&checksum_input) != 1 {
        return Err(bad("checksum failed"));
    }

    let payload = five.get(..five.len() - 6).ok_or_else(|| bad("truncated"))?;
    let bytes = convert_bits(payload, 5, 8, false).ok_or_else(|| bad("regroup failed"))?;

    Ok((hrp.to_owned(), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_lengths() {
        for len in [0_usize, 1, 32, 33, 1216, 1220] {
            let data: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let s = encode("age1pq", &data).expect("encode");
            let (hrp, back) = decode(&s).expect("decode");
            assert_eq!(hrp, "age1pq");
            assert_eq!(back, data, "len {len}");
        }
    }

    #[test]
    fn agrees_with_the_age_crate_on_a_real_recipient() {
        // The strongest check available without a second bech32 implementation:
        // take a recipient string the `age` crate produced, decode it here, and
        // re-encode. Any disagreement in charset, checksum or bit regrouping
        // shows up as a mismatch.
        let id = age::x25519::Identity::generate();
        let encoded = id.to_public().to_string();
        let (hrp, bytes) = decode(&encoded).expect("decode an age recipient");
        assert_eq!(hrp, "age");
        assert_eq!(bytes.len(), 32);
        assert_eq!(encode("age", &bytes).expect("re-encode"), encoded);
    }

    #[test]
    fn a_long_pq_sized_payload_encodes() {
        // 1216 bytes is the hybrid public key. The `bech32` crate refuses this
        // because of the 90-character BIP-0173 code limit; we must not.
        let s = encode("age1pq", &vec![0x5a; 1216]).expect("encode 1216 bytes");
        assert!(s.len() > 1900, "expected ~1960 characters, got {}", s.len());
        assert!(s.starts_with("age1pq1"));
    }

    #[test]
    fn a_flipped_character_fails_the_checksum() {
        let s = encode("age1pq", &[1, 2, 3, 4]).expect("encode");
        let mut bytes = s.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'q' { b'p' } else { b'q' };
        let broken = String::from_utf8(bytes).expect("utf8");
        assert!(decode(&broken).is_err());
    }

    #[test]
    fn mixed_case_is_rejected() {
        assert!(decode("Age1Pq1qqqq").is_err());
    }
}
