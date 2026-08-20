//! Compact USTAR, used to bundle several files into one payload before age
//! encryption (so a multi-file encrypt produces one `.tar.age`).
//!
//! A direct port of Android's `archive/TarArchive.kt`. "Compact" means the
//! archive is exactly the entry blocks followed by the two zero blocks that mark
//! end-of-archive, with no padding out to a 10240-byte record. Headers use fixed
//! fields (mode `0644`, uid/gid `0`, empty uname/gname, mtime `0`) so the same
//! set of files always produces the same bytes — matching the iOS and Android
//! reference archives byte for byte. Standard `tar` tools extract it normally.
//!
//! The Rust `tar` crate is deliberately *not* used here: it writes uname/gname,
//! a real mtime, and record padding, none of which the reference format has.
//! This is a from-the-spec implementation so the bytes match exactly.

use crate::error::{CoreError, Result};

const BLOCK: usize = 512;
const NAME_MAX: usize = 100;
const MODE_0644: u64 = 0o644;

/// Largest entry a USTAR 12-byte octal size field can express: `8^11 - 1`.
pub const MAX_ENTRY_SIZE: u64 = 8_589_934_591;

/// One entry of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry name (path). At most 100 UTF-8 bytes.
    pub name: String,
    /// The file contents.
    pub data: Vec<u8>,
}

/// Build a compact USTAR archive from `entries`, with a fixed mtime of 0.
///
/// # Errors
///
/// [`CoreError::Signing`] (used here as a generic archive error) if a name is
/// longer than 100 bytes or an entry exceeds [`MAX_ENTRY_SIZE`].
pub fn create(entries: &[Entry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for e in entries {
        write_entry(&mut out, &e.name, &e.data)?;
    }
    out.extend(std::iter::repeat_n(0_u8, BLOCK * 2));
    Ok(out)
}

fn write_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) -> Result<()> {
    out.extend_from_slice(&header(name, data.len() as u64, 0)?);
    out.extend_from_slice(data);
    let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
    out.extend(std::iter::repeat_n(0_u8, pad));
    Ok(())
}

/// Parse a compact USTAR archive.
///
/// # Errors
///
/// [`CoreError::Signing`] if the archive is not a multiple of 512, a header
/// checksum is wrong, or an entry's size runs past the end.
pub fn extract(archive: &[u8]) -> Result<Vec<Entry>> {
    if archive.len() % BLOCK != 0 {
        return Err(tar_err("tar size is not a multiple of 512"));
    }
    let mut entries = Vec::new();
    let mut off = 0;
    while off + BLOCK <= archive.len() {
        let header = archive
            .get(off..off + BLOCK)
            .ok_or_else(|| tar_err("truncated header"))?;
        if header.iter().all(|&b| b == 0) {
            break; // end-of-archive marker
        }
        verify_checksum(header)?;
        let name = read_string(header, 0, NAME_MAX);
        let size = read_octal(header, 124, 12)? as usize;
        off += BLOCK;
        let end = off
            .checked_add(size)
            .filter(|&e| e <= archive.len())
            .ok_or_else(|| tar_err("entry size exceeds archive"))?;
        let data = archive
            .get(off..end)
            .ok_or_else(|| tar_err("entry size exceeds archive"))?
            .to_vec();
        entries.push(Entry { name, data });
        off += size.div_ceil(BLOCK) * BLOCK;
    }
    Ok(entries)
}

// -------------------------------------------------------------- internals ---

fn header(name: &str, size: u64, mtime: u64) -> Result<[u8; BLOCK]> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > NAME_MAX {
        return Err(tar_err("name too long for USTAR (max 100)"));
    }
    if size > MAX_ENTRY_SIZE {
        return Err(tar_err("entry is too large for USTAR"));
    }
    let mut h = [0_u8; BLOCK];
    h.get_mut(..name_bytes.len())
        .ok_or_else(|| tar_err("name overflow"))?
        .copy_from_slice(name_bytes);
    write_octal(&mut h, 100, 8, MODE_0644)?; // mode
    write_octal(&mut h, 108, 8, 0)?; // uid
    write_octal(&mut h, 116, 8, 0)?; // gid
    write_octal(&mut h, 124, 12, size)?; // size
    write_octal(&mut h, 136, 12, mtime)?; // mtime
    for i in 148..156 {
        set(&mut h, i, b' ')?; // checksum field as spaces while summing
    }
    set(&mut h, 156, b'0')?; // typeflag: regular file
    for (i, &b) in b"ustar".iter().enumerate() {
        set(&mut h, 257 + i, b)?; // "ustar\0"
    }
    set(&mut h, 263, b'0')?; // version "00"
    set(&mut h, 264, b'0')?;
    write_checksum(&mut h)?;
    Ok(h)
}

fn write_checksum(h: &mut [u8; BLOCK]) -> Result<()> {
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let s = format!("{sum:06o}");
    if s.len() > 6 {
        return Err(tar_err("checksum overflow"));
    }
    for (i, b) in s.bytes().enumerate() {
        set(h, 148 + i, b)?;
    }
    set(h, 154, 0)?; // null
    set(h, 155, b' ')?; // space
    Ok(())
}

fn verify_checksum(header: &[u8]) -> Result<()> {
    let stored = read_octal(header, 148, 8)?;
    let mut calc = header.to_vec();
    for i in 148..156 {
        *calc.get_mut(i).ok_or_else(|| tar_err("short header"))? = b' ';
    }
    let sum: u64 = calc.iter().map(|&b| u64::from(b)).sum();
    if sum != stored {
        return Err(tar_err("tar header checksum mismatch"));
    }
    Ok(())
}

fn write_octal(buf: &mut [u8; BLOCK], off: usize, field_len: usize, value: u64) -> Result<()> {
    let digits = field_len - 1;
    let s = format!("{value:0width$o}", width = digits);
    if s.len() > digits {
        return Err(tar_err("octal field overflow"));
    }
    for (i, b) in s.bytes().enumerate() {
        set(buf, off + i, b)?;
    }
    set(buf, off + digits, 0)?;
    Ok(())
}

fn read_octal(buf: &[u8], off: usize, len: usize) -> Result<u64> {
    let mut s = String::new();
    for i in off..off + len {
        let c = *buf.get(i).ok_or_else(|| tar_err("short numeric field"))?;
        if c == 0 || c == b' ' {
            if s.is_empty() {
                continue;
            }
            break;
        }
        s.push(c as char);
    }
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(&s, 8).map_err(|_| tar_err("non-octal numeric field"))
}

fn read_string(buf: &[u8], off: usize, len: usize) -> String {
    let mut end = off;
    while end < off + len && buf.get(end).copied().unwrap_or(0) != 0 {
        end += 1;
    }
    String::from_utf8_lossy(buf.get(off..end).unwrap_or_default()).into_owned()
}

fn set(buf: &mut [u8; BLOCK], i: usize, b: u8) -> Result<()> {
    *buf.get_mut(i).ok_or_else(|| tar_err("header index overflow"))? = b;
    Ok(())
}

/// Archive errors reuse the generic `Signing` variant to avoid growing the error
/// enum for one more subsystem; the message says what actually went wrong.
fn tar_err(msg: &str) -> CoreError {
    CoreError::Signing(format!("tar: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, data: &[u8]) -> Entry {
        Entry {
            name: name.to_owned(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn round_trips_several_entries() {
        let entries = vec![
            entry("a.txt", b"hello"),
            entry("b.bin", &[0_u8; 700]),
            entry("c", b""),
        ];
        let archive = create(&entries).expect("create");
        assert_eq!(extract(&archive).expect("extract"), entries);
    }

    #[test]
    fn the_archive_is_deterministic() {
        // Same inputs, same bytes — the whole point of the fixed header fields.
        let e = vec![entry("x", b"data")];
        assert_eq!(create(&e).unwrap(), create(&e).unwrap());
    }

    #[test]
    fn header_fields_match_the_ustar_spec() {
        let archive = create(&[entry("note.txt", b"hi")]).unwrap();
        // name
        assert_eq!(&archive[0..8], b"note.txt");
        // mode 0644 as "0000644\0"
        assert_eq!(&archive[100..108], b"0000644\0");
        // size 2 as "00000000002\0"
        assert_eq!(&archive[124..136], b"00000000002\0");
        // ustar magic
        assert_eq!(&archive[257..263], b"ustar\0");
        // version "00"
        assert_eq!(&archive[263..265], b"00");
        // typeflag regular file
        assert_eq!(archive[156], b'0');
        // ends with two zero blocks
        assert!(archive[archive.len() - 1024..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_512_aligned_payload_needs_no_padding() {
        let data = vec![7_u8; 512];
        let archive = create(&[entry("full", &data)]).unwrap();
        // header(512) + data(512) + end(1024)
        assert_eq!(archive.len(), 512 + 512 + 1024);
    }

    #[test]
    fn a_bad_checksum_is_rejected() {
        let mut archive = create(&[entry("x", b"data")]).unwrap();
        archive[0] = b'y'; // change the name, invalidating the checksum
        assert!(extract(&archive).is_err());
    }

    #[test]
    fn a_name_over_100_bytes_is_refused() {
        let long = "a".repeat(101);
        assert!(create(&[entry(&long, b"x")]).is_err());
    }

    #[test]
    fn a_non_block_multiple_is_rejected() {
        assert!(extract(&[0_u8; 500]).is_err());
    }
}
