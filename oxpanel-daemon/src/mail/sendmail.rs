//! OxPanel's sendmail: `oxpanel-daemon sendmail [-t] [-i] [-f sender] [--] [recipient…]`.
//!
//! PHP's `sendmail_path` (and anything else a site runs) calls this instead
//! of Postfix's sendmail. It reads the message and hands it to the mail
//! policy service over its socket, which identifies the account by the
//! connection's uid, checks the sender and the hourly limit, and passes it
//! to Postfix. When the caller is not a hosting account (root's scripts),
//! or email is not switched on (no service), the message goes to Postfix's
//! own sendmail unchanged — which, with email on, only root may use.
//!
//! Exit codes follow sendmail's (sysexits): 0 sent, 64 usage, 65 refused
//! message, 75 try again later (a limit), 77 refused sender.

use std::io::Read as _;
use std::path::PathBuf;

use super::policy::SubmitRequest;
use crate::system::{bin, CommandSpec, RealSystem, System};

pub const SUBCOMMAND: &str = "sendmail";
const SOCKET: &str = "/run/oxpanel-mail/sendmail.sock";
const MAX_MESSAGE: u64 = 200 * 1024 * 1024;

const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_UNAVAILABLE: u8 = 69;
const EX_TEMPFAIL: u8 = 75;
const EX_NOPERM: u8 = 77;

/// The arguments sendmail is commonly given; anything else is refused.
pub fn parse_args(args: &[String]) -> Result<SubmitRequest, String> {
    let mut req = SubmitRequest::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                req.recipients.extend(it.by_ref().cloned());
                break;
            }
            "-t" => req.extract = true,
            // Dots alone on a line are data (always true here); options and
            // modes without effect.
            "-i" | "-oi" | "-odb" | "-odi" | "-om" | "-v" => {}
            "-f" | "-r" => req.sender = Some(it.next().ok_or("-f needs an address")?.clone()),
            "-F" => {
                it.next().ok_or("-F needs a name")?;
            }
            s if s.starts_with("-f") || s.starts_with("-r") => {
                req.sender = s.get(2..).map(str::to_owned);
            }
            s if s.starts_with("-F")
                || s.starts_with("-o")
                || s.starts_with("-B")
                || s.starts_with("-N") => {}
            s if s.starts_with('-') => return Err(format!("unsupported option {s}")),
            s => req.recipients.push(s.to_owned()),
        }
    }
    // `-f <>` (or an empty -f): the null sender, as autoresponders use it.
    if req.sender.as_deref() == Some("") {
        req.sender = Some("<>".to_owned());
    }
    Ok(req)
}

/// Postfix's own sendmail with the same arguments and message.
fn fall_back(args: &[String], msg: Vec<u8>) -> u8 {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return EX_UNAVAILABLE;
    };
    let spec = CommandSpec::new(bin::SENDMAIL, std::time::Duration::from_secs(300))
        .args(args)
        .stdin(msg);
    match rt.block_on(RealSystem::new().run(spec)) {
        Ok(out) if out.success() => 0,
        Ok(out) => {
            eprint_line(&out.combined_lossy());
            u8::try_from(out.code.unwrap_or(1)).unwrap_or(1)
        }
        Err(e) => {
            eprint_line(&e.to_string());
            EX_UNAVAILABLE
        }
    }
}

fn eprint_line(s: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "sendmail: {}", s.trim());
}

/// `oxpanel-daemon sendmail …` (`args` after the subcommand).
pub fn main(args: &[String]) -> u8 {
    let req = match parse_args(args) {
        Ok(r) => r,
        Err(e) => {
            eprint_line(&e);
            return EX_USAGE;
        }
    };
    let mut msg = Vec::new();
    if std::io::stdin()
        .take(MAX_MESSAGE + 1)
        .read_to_end(&mut msg)
        .is_err()
        || msg.len() as u64 > MAX_MESSAGE
    {
        eprint_line("the message could not be read or is too large");
        return EX_DATAERR;
    }
    let socket = std::env::var_os("OXPANEL_SENDMAIL_SOCKET")
        .map_or_else(|| PathBuf::from(SOCKET), PathBuf::from);
    // No service: email is not on here.
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&socket) else {
        return fall_back(args, msg);
    };
    let answer = (|| -> std::io::Result<String> {
        use std::io::{BufRead as _, Write as _};
        let head = serde_json::to_string(&req).map_err(std::io::Error::other)?;
        stream.write_all(head.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.write_all(&msg)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut line = String::new();
        std::io::BufReader::new(stream.take(4096)).read_line(&mut line)?;
        Ok(line)
    })();
    let answer = match answer {
        Ok(a) => a,
        Err(e) => {
            eprint_line(&format!("the mail service did not answer: {e}"));
            return EX_TEMPFAIL;
        }
    };
    let (code, text) = answer.trim().split_once(' ').unwrap_or((answer.trim(), ""));
    match code {
        "OK" => 0,
        "NOTACCOUNT" => fall_back(args, msg),
        "TEMP" => {
            eprint_line(text);
            EX_TEMPFAIL
        }
        _ if text.contains("sender") || text.contains("From:") || text.contains("suspended") => {
            eprint_line(text);
            EX_NOPERM
        }
        _ => {
            eprint_line(text);
            EX_DATAERR
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn the_usual_sendmail_arguments_are_understood() {
        let r = parse_args(&s(&["-t", "-i", "-fshop@x.test"])).unwrap();
        assert!(r.extract);
        assert_eq!(r.sender.as_deref(), Some("shop@x.test"));
        let r = parse_args(&s(&[
            "-oi",
            "-f",
            "a@b.test",
            "-F",
            "Shop",
            "--",
            "c@d.test",
            "-x@e.test",
        ]))
        .unwrap();
        assert_eq!(r.sender.as_deref(), Some("a@b.test"));
        assert_eq!(r.recipients, ["c@d.test", "-x@e.test"]);
        assert!(parse_args(&s(&["-bs"])).is_err());
        assert!(parse_args(&s(&["-C/etc/evil.cf"])).is_err());
        assert!(parse_args(&s(&["-f"])).is_err());
    }
}
