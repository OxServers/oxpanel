//! Mailbox passwords: stored only as a bcrypt hash in the form Dovecot
//! verifies (`{BLF-CRYPT}$2y$12$…`), computed here so the password never
//! leaves the daemon: it is not an argument of any program, not in a log,
//! not in a record and not in a response.

use crate::error::{Error, Result};
use crate::validate::MailPassword;

/// bcrypt's cost: 2^12 rounds (about a quarter of a second per login on a
/// current core; Dovecot's authentication cache keeps repeated logins cheap).
pub const COST: u32 = 12;
const PREFIX: &str = "{BLF-CRYPT}";

/// The hash Dovecot stores for `password`.
pub fn hash(password: &MailPassword) -> Result<String> {
    hash_with_cost(password, COST)
}

/// [`hash`] with another cost (tests use the cheapest).
pub fn hash_with_cost(password: &MailPassword, cost: u32) -> Result<String> {
    let parts = bcrypt::hash_with_result(password.expose(), cost)
        .map_err(|e| Error::Internal(format!("bcrypt: {e}")))?;
    Ok(format!(
        "{PREFIX}{}",
        parts.format_for_version(bcrypt::Version::TwoY)
    ))
}

/// Whether `stored` is a hash this module produced: `{BLF-CRYPT}$2y$NN$`
/// followed by bcrypt's 53 characters of `./A-Za-z0-9`. Anything else
/// (a plain password, a line break) never reaches Dovecot's password file.
pub fn is_hash(stored: &str) -> bool {
    let Some(rest) = stored
        .strip_prefix(PREFIX)
        .and_then(|r| r.strip_prefix("$2y$"))
    else {
        return false;
    };
    let Some((cost, tail)) = rest.split_once('$') else {
        return false;
    };
    cost.len() == 2
        && cost.bytes().all(|b| b.is_ascii_digit())
        && tail.len() == 53
        && tail
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
}

/// Whether `password` matches `stored` (tests and the integration check).
pub fn verify(password: &str, stored: &str) -> bool {
    stored
        .strip_prefix(PREFIX)
        .is_some_and(|h| bcrypt::verify(password, h).unwrap_or(false))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::validate::{Domain, MailLocalPart};

    #[test]
    fn hashes_are_bcrypt_in_dovecots_form_and_never_the_password() {
        let local = MailLocalPart::parse("info").unwrap();
        let domain = Domain::parse("example.com").unwrap();
        let pw = MailPassword::parse("correct horse battery", &local, &domain).unwrap();
        let h = hash_with_cost(&pw, 4).unwrap();
        assert!(h.starts_with("{BLF-CRYPT}$2y$04$"), "{h}");
        assert!(is_hash(&h));
        assert!(!h.contains("horse"));
        assert!(verify("correct horse battery", &h));
        assert!(!verify("correct horse batterY", &h));
        assert!(format!("{pw:?}").contains("redacted"));
        for bad in [
            "",
            "secret",
            "{BLF-CRYPT}$2y$12$short",
            "{PLAIN}x",
            &format!("{h}\nroot"),
        ] {
            assert!(!is_hash(bad), "{bad}");
        }
    }
}
