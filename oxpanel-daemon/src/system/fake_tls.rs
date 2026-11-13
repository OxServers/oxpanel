//! Stand-ins for OpenSSL and the ACME client, for [`super::FakeSystem`].
//!
//! Real X.509 cannot be produced without a cryptographic library, and the
//! workflows do not need it: they only ask OpenSSL who issued a certificate,
//! when it is valid, which names it covers and which key it belongs to. A
//! fake certificate therefore is an ordinary PEM block whose body spells
//! those answers out, and the fake `openssl` reads them back. The PEM
//! handling of the daemon itself runs unchanged on these blocks; real
//! certificates are exercised by `tests-integration/run-inside.sh`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::records::now_unix;
use crate::tls::format_utc;

/// Issuer of the certificates the fake ACME client "obtains".
pub const FAKE_ACME_ISSUER: &str = "CN=Fake ACME CA";

fn pem(label: &str, text: &str) -> String {
    let body = STANDARD.encode(text);
    let mut out = format!("-----BEGIN {label}-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(64));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// A private key the fake `openssl` recognises. Two keys are "the same key"
/// when their ids are equal.
pub fn fake_private_key(id: &str) -> String {
    pem("PRIVATE KEY", &format!("fake-key\nkey={id}\n"))
}

/// A certificate for the key `key_id`, as the fake `openssl` understands it.
pub fn fake_certificate(
    key_id: &str,
    issuer: &str,
    not_before_unix: u64,
    not_after_unix: u64,
    names: &[&str],
) -> String {
    pem(
        "CERTIFICATE",
        &format!(
            "fake-cert\nkey={key_id}\nissuer={issuer}\nnot_before={}\nnot_after={}\nnames={}\n",
            format_utc(not_before_unix),
            format_utc(not_after_unix),
            names.join(",")
        ),
    )
}

/// The fields of the first PEM block in `path`, if it is a fake of `kind`.
fn decode(path: Option<&String>, kind: &str) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(Path::new(path?)).ok()?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN "))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END "))
        .collect();
    let decoded = String::from_utf8(STANDARD.decode(body).ok()?).ok()?;
    let mut lines = decoded.lines();
    if lines.next()? != kind {
        return None;
    }
    Some(
        lines
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}

/// The value following `flag` in `args`.
fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a String> {
    args.get(args.iter().position(|a| a == flag)? + 1)
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fields.get(key).map_or("", String::as_str)
}

/// `openssl <args>`: exit code, standard output, standard error.
/// `generated` counts the keys handed out by `genpkey`.
pub(super) fn openssl(args: &[OsString], generated: &mut u32) -> (i32, String, String) {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let public_key =
        |f: &BTreeMap<String, String>| format!("FAKE PUBLIC KEY {}\n", field(f, "key"));
    let answer = match args.first().map(String::as_str) {
        Some("genpkey") => {
            *generated += 1;
            Some(fake_private_key(&format!("generated-{generated}")))
        }
        Some("pkey") => decode(value(&args, "-in"), "fake-key").map(|f| public_key(&f)),
        Some("req") => decode(value(&args, "-key"), "fake-key").map(|f| {
            let names = value(&args, "-addext")
                .and_then(|v| v.strip_prefix("subjectAltName="))
                .unwrap_or_default()
                .replace("DNS:", "");
            pem(
                "CERTIFICATE REQUEST",
                &format!("fake-csr\nkey={}\nnames={names}\n", field(&f, "key")),
            )
        }),
        Some("x509") => decode(value(&args, "-in"), "fake-cert").map(|f| {
            if has("-pubkey") {
                public_key(&f)
            } else if has("-ext") {
                let names = field(&f, "names");
                if names.is_empty() {
                    String::new()
                } else {
                    let list: Vec<String> = names.split(',').map(|n| format!("DNS:{n}")).collect();
                    format!(
                        "X509v3 Subject Alternative Name: \n    {}\n",
                        list.join(", ")
                    )
                }
            } else {
                format!(
                    "issuer={}\nnotBefore={}\nnotAfter={}\n",
                    field(&f, "issuer"),
                    field(&f, "not_before"),
                    field(&f, "not_after")
                )
            }
        }),
        _ => None,
    };
    match answer {
        Some(stdout) => (0, stdout, String::new()),
        None => (1, String::new(), "Could not read the input".to_owned()),
    }
}

/// The ACME client inside its transient unit: "obtains" a certificate for
/// the names of the signing request, valid from an hour ago for `lifetime`
/// seconds, and delivers it. Returns the exit code and what was printed.
pub(super) fn acme_client(args: &[OsString], lifetime: u64) -> (i32, String) {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (Some(csr), Some(out)) = (
        decode(value(&args, "--csr"), "fake-csr"),
        value(&args, "--out"),
    ) else {
        return (1, "no signing request".to_owned());
    };
    let names: Vec<&str> = field(&csr, "names").split(',').collect();
    let now = now_unix();
    let chain = fake_certificate(
        field(&csr, "key"),
        FAKE_ACME_ISSUER,
        now.saturating_sub(3600),
        now.saturating_add(lifetime),
        &names,
    );
    match std::fs::write(out, chain) {
        Ok(()) => (0, String::new()),
        Err(e) => (1, format!("cannot deliver the certificate: {e}")),
    }
}
