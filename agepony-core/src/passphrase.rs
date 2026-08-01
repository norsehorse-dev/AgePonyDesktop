//! How much scrypt work AgePony spends, and how much it will spend for someone
//! else.
//!
//! The `age` crate picks a work factor by timing whatever machine it happens to
//! be running on, and the decrypting side independently times *its* machine and
//! then refuses anything more than four doublings above that measurement. Two
//! consequences, both bad. The same passphrase produces a differently-shaped
//! file on different hardware. And a file written on a fast machine can be
//! permanently unopenable on a slow one -- or on the same machine under load,
//! since the measurement is a single wall-clock sample and a scheduler hiccup
//! is enough to skew it. That second case is not hypothetical: it is how CI
//! found this, with encryption picking 2^20 and decryption, seconds later on
//! the same runner, refusing anything above 2^17.
//!
//! Being locked out of your own file because a core was busy is not a security
//! property. So AgePony pins both ends and never measures: it writes
//! [`WORK_FACTOR`] and it opens anything up to [`MAX_WORK_FACTOR`].

use crate::Result;
use age::secrecy::SecretString;

/// The work factor AgePony writes: `N = 2^18`, roughly 256 MiB and a second.
///
/// The same value the iOS and Android apps write, so a passphrase file is
/// byte-shaped the same whichever pony made it.
pub const WORK_FACTOR: u8 = 18;

/// The highest work factor AgePony will accept from a file: `N = 2^22`, or
/// about 4 GiB.
///
/// A desktop can afford to open a file a phone cannot, so this sits well above
/// what AgePony itself writes. Past it, the work is not merely slow but beyond
/// any machine AgePony targets, and refusing is more honest than thrashing
/// swap until the user force-quits.
pub const MAX_WORK_FACTOR: u8 = 22;

/// A passphrase recipient fixed at [`WORK_FACTOR`], whatever the hardware.
pub fn recipient(passphrase: SecretString) -> age::scrypt::Recipient {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(WORK_FACTOR);
    recipient
}

/// A passphrase identity that accepts any file up to [`MAX_WORK_FACTOR`].
pub fn identity(passphrase: SecretString) -> age::scrypt::Identity {
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    identity
}

/// An encryptor for a passphrase, at AgePony's fixed work factor.
///
/// The drop-in replacement for [`age::Encryptor::with_user_passphrase`], which
/// measures the machine instead.
///
/// # Errors
///
/// [`crate::CoreError::Encrypt`] cannot actually occur for a lone scrypt
/// recipient -- age only rejects recipient *sets* -- but the error is returned
/// rather than unwrapped so that stays age's business and not an assumption
/// baked in here.
pub fn encryptor(passphrase: SecretString) -> Result<age::Encryptor> {
    let recipient = recipient(passphrase);
    Ok(age::Encryptor::with_recipients(std::iter::once(
        &recipient as &dyn age::Recipient,
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read the `log_n` argument out of the scrypt stanza of an age header.
    ///
    /// The v1 header is plain ASCII up to the payload, and the stanza is
    /// `-> scrypt <base64 salt> <log_n>`.
    fn stanza_work_factor(file: &[u8]) -> u8 {
        let text = String::from_utf8_lossy(&file[..file.len().min(256)]).into_owned();
        let line = text
            .lines()
            .find(|l| l.starts_with("-> scrypt "))
            .expect("the file must have an scrypt stanza");
        line.split_whitespace()
            .nth(3)
            .expect("stanza has salt and log_n")
            .parse()
            .expect("log_n is a decimal number")
    }

    fn encrypt(passphrase: &str) -> Vec<u8> {
        let encryptor = encryptor(SecretString::from(passphrase.to_owned())).expect("encryptor");
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).expect("wrap");
        std::io::Write::write_all(&mut writer, b"pony").expect("write");
        writer.finish().expect("finish");
        out
    }

    fn decrypt(file: &[u8], passphrase: &str) -> Result<Vec<u8>> {
        let decryptor = age::Decryptor::new(file)?;
        let identity = identity(SecretString::from(passphrase.to_owned()));
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut out)?;
        Ok(out)
    }

    #[test]
    fn we_write_the_work_factor_we_promise() {
        assert_eq!(stanza_work_factor(&encrypt("correct horse")), WORK_FACTOR);
    }

    #[test]
    fn the_work_factor_does_not_depend_on_the_machine() {
        // age's default would be free to differ between these two calls; ours
        // is a constant, so the header bytes after the salt must agree.
        assert_eq!(
            stanza_work_factor(&encrypt("one")),
            stanza_work_factor(&encrypt("two"))
        );
    }

    #[test]
    fn what_we_write_is_what_we_read() {
        let file = encrypt("correct horse battery staple");
        assert_eq!(
            decrypt(&file, "correct horse battery staple").expect("round trip"),
            b"pony"
        );
    }

    #[test]
    fn a_wrong_passphrase_is_still_refused() {
        let file = encrypt("correct horse");
        assert!(decrypt(&file, "wrong horse").is_err());
    }

    /// The bug this module exists for: a file written above the work factor
    /// this machine would have measured must still open.
    #[test]
    fn a_file_from_a_faster_machine_still_opens() {
        let passphrase = SecretString::from("correct horse".to_owned());
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        // Two doublings past ours, and past what age's own default ceiling
        // would allow on a runner that measured itself as slow.
        recipient.set_work_factor(WORK_FACTOR + 2);

        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .expect("encryptor");
        let mut file = Vec::new();
        let mut writer = encryptor.wrap_output(&mut file).expect("wrap");
        std::io::Write::write_all(&mut writer, b"pony").expect("write");
        writer.finish().expect("finish");

        assert_eq!(stanza_work_factor(&file), WORK_FACTOR + 2);
        assert_eq!(
            decrypt(&file, "correct horse").expect("still opens"),
            b"pony"
        );
    }

    #[test]
    fn we_refuse_work_beyond_the_ceiling() {
        // Built by hand rather than by encrypting: actually running 2^23 scrypt
        // to make the fixture would cost 8 GiB, which is the whole point of
        // refusing it. A forged stanza is enough, because the ceiling is
        // checked before any work is done.
        let file = encrypt("correct horse");
        let text = String::from_utf8_lossy(&file[..file.len().min(256)]).into_owned();
        let line = text
            .lines()
            .find(|l| l.starts_with("-> scrypt "))
            .expect("stanza");
        let forged = line.replace(
            &format!(" {WORK_FACTOR}"),
            &format!(" {}", MAX_WORK_FACTOR + 1),
        );
        assert_ne!(line, forged, "the substitution must have happened");

        let mut tampered = Vec::new();
        let cut = text.find(line).expect("stanza is in the prefix");
        tampered.extend_from_slice(&file[..cut]);
        tampered.extend_from_slice(forged.as_bytes());
        tampered.extend_from_slice(&file[cut + line.len()..]);

        assert!(decrypt(&tampered, "correct horse").is_err());
    }
}
