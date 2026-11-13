//! `oxpanel-acme` — obtain one certificate from an ACME certificate authority
//! (RFC 8555) using the HTTP-01 challenge.
//!
//! `oxpanel-daemon` has no network, so it starts this program in a transient
//! systemd unit, as the unprivileged account `oxpanel-acme`, once per
//! certificate. The division of labour keeps this program harmless:
//!
//! - it is given a signing request (CSR) and returns a certificate chain.
//!   Both are public. It never sees the private key of a site;
//! - the only secret it owns is its ACME account key, in `--account-dir`;
//! - it writes challenge files into `--challenge-dir` (which the web server
//!   publishes under `/.well-known/acme-challenge/`) and removes them again;
//! - whatever it writes to `--out` is validated by the daemon against the
//!   key only the daemon holds, so a wrong answer cannot be installed.
//!
//! Trust: the certificate authority's own HTTPS certificate is verified
//! against the operating system's trust store, or against `--ca-file` for a
//! private or test authority.
//!
//! Exit status 0 = the chain is in `--out`; anything else = no certificate,
//! and the reason is on standard error (which systemd puts in the journal).
// Its standard error *is* its interface: the daemon relays it to the caller.
#![allow(clippy::print_stderr)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

/// Errors are sentences for the journal.
type Res<T> = Result<T, String>;

/// The trust store of AlmaLinux and its relatives.
const SYSTEM_CA_BUNDLE: &str = "/etc/pki/tls/certs/ca-bundle.crt";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// How often and how long to wait for the authority to validate or issue.
const POLL_ATTEMPTS: u32 = 40;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How often a request refused for a stale nonce is repeated.
const NONCE_RETRIES: u32 = 8;
const USAGE: &str = "usage: oxpanel-acme --directory URL [--ca-file FILE] [--email ADDRESS] \
--account-dir DIR --challenge-dir DIR --csr FILE --out FILE --domain NAME [--domain NAME]...";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    directory: String,
    ca_file: Option<PathBuf>,
    email: Option<String>,
    account_dir: PathBuf,
    challenge_dir: PathBuf,
    csr: PathBuf,
    out: PathBuf,
    domains: Vec<String>,
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Res<Args> {
    let mut args = Args::default();
    while let Some(flag) = argv.next() {
        let value = argv
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--directory" => args.directory = value,
            "--ca-file" => args.ca_file = Some(value.into()),
            "--email" => args.email = Some(value),
            "--account-dir" => args.account_dir = value.into(),
            "--challenge-dir" => args.challenge_dir = value.into(),
            "--csr" => args.csr = value.into(),
            "--out" => args.out = value.into(),
            "--domain" => args.domains.push(value),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    let missing = [
        ("--directory", args.directory.is_empty()),
        ("--account-dir", args.account_dir.as_os_str().is_empty()),
        ("--challenge-dir", args.challenge_dir.as_os_str().is_empty()),
        ("--csr", args.csr.as_os_str().is_empty()),
        ("--out", args.out.as_os_str().is_empty()),
        ("--domain", args.domains.is_empty()),
    ];
    if let Some((flag, _)) = missing.iter().find(|(_, absent)| *absent) {
        return Err(format!("{flag} is required\n{USAGE}"));
    }
    if !args.directory.starts_with("https://") {
        return Err("--directory must be an https:// URL".into());
    }
    Ok(args)
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// The DER bytes of the first PEM block in `pem`.
fn pem_to_der(pem: &str) -> Res<Vec<u8>> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN "))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END "))
        .collect();
    if body.is_empty() {
        return Err("the signing request is not PEM".into());
    }
    STANDARD
        .decode(body)
        .map_err(|e| format!("the signing request is not valid base64: {e}"))
}

/// A challenge token becomes a file name: accept only what RFC 8555 allows
/// (base64url characters), so a hostile authority cannot name another file.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The ACME account: an ECDSA P-256 key, kept in `--account-dir`.
struct Account {
    key: EcdsaKeyPair,
    rng: SystemRandom,
    /// The public key as a JSON Web Key.
    jwk: Value,
    /// RFC 7638 thumbprint of the key; part of every challenge response.
    thumbprint: String,
}

impl Account {
    /// Load the account key for `directory`, creating it on first use. Each
    /// directory (production, staging, a test authority) gets its own key.
    fn load_or_create(dir: &Path, directory: &str) -> Res<Self> {
        let rng = SystemRandom::new();
        let id: String =
            sha256(directory.as_bytes())
                .iter()
                .take(8)
                .fold(String::new(), |mut hex, b| {
                    let _ = write!(hex, "{b:02x}");
                    hex
                });
        let path = dir.join(format!("{id}.pk8"));
        let pkcs8 = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|_| "cannot generate an account key".to_owned())?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
                file.write_all(doc.as_ref())
                    .and_then(|()| file.sync_all())
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                eprintln!("created a new ACME account key for {directory}");
                doc.as_ref().to_vec()
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|e| format!("{} is not a usable account key: {e}", path.display()))?;
        // An uncompressed point: 0x04, then X and Y, 32 bytes each.
        let point = key.public_key().as_ref();
        let (x, y) = match (point.get(1..33), point.get(33..65)) {
            (Some(x), Some(y)) => (b64url(x), b64url(y)),
            _ => return Err("unexpected public key encoding".into()),
        };
        // RFC 7638: required members only, in lexicographic order, no whitespace.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        Ok(Self {
            thumbprint: b64url(&sha256(canonical.as_bytes())),
            jwk: json!({"crv": "P-256", "kty": "EC", "x": x, "y": y}),
            key,
            rng,
        })
    }

    /// A JWS (flattened JSON serialisation) over `payload` for `url`.
    /// `payload` `None` is the empty payload of a POST-as-GET.
    fn sign(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> Res<String> {
        let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
        match (kid, protected.as_object_mut()) {
            (Some(kid), Some(p)) => p.insert("kid".into(), json!(kid)),
            (None, Some(p)) => p.insert("jwk".into(), self.jwk.clone()),
            (_, None) => None,
        };
        let protected = b64url(protected.to_string().as_bytes());
        let payload = payload.map_or_else(String::new, |p| b64url(p.to_string().as_bytes()));
        let signature = self
            .key
            .sign(&self.rng, format!("{protected}.{payload}").as_bytes())
            .map_err(|_| "cannot sign the request".to_owned())?;
        Ok(json!({
            "protected": protected,
            "payload": payload,
            "signature": b64url(signature.as_ref()),
        })
        .to_string())
    }
}

/// What came back from the authority.
struct Reply {
    status: u16,
    location: Option<String>,
    body: String,
}

impl Reply {
    fn json(&self) -> Res<Value> {
        serde_json::from_str(&self.body)
            .map_err(|e| format!("the authority sent something that is not JSON: {e}"))
    }
}

/// A string member of a JSON object.
fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// A string member that must be there.
fn required<'a>(v: &'a Value, key: &str, of: &str) -> Res<&'a str> {
    text(v, key).ok_or_else(|| format!("the authority's {of} has no '{key}'"))
}

/// The human-readable part of an RFC 7807 problem document.
fn problem(body: &str) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|v| text(v, key))
            .unwrap_or_default()
            .to_owned()
    };
    let (kind, detail) = (field("type"), field("detail"));
    match (kind.is_empty(), detail.is_empty()) {
        (true, true) => body.chars().take(300).collect(),
        (false, true) => kind,
        (true, false) => detail,
        (false, false) => format!("{detail} ({kind})"),
    }
}

struct Client {
    agent: ureq::Agent,
    account: Account,
    new_nonce: String,
    nonce: Option<String>,
    /// The account URL, once registered.
    kid: Option<String>,
}

fn trust_roots(ca_file: Option<&Path>) -> Res<ureq::tls::RootCerts> {
    let path = ca_file.unwrap_or(Path::new(SYSTEM_CA_BUNDLE));
    let pem = std::fs::read(path).map_err(|e| {
        format!(
            "cannot read the trusted certificates in {}: {e}",
            path.display()
        )
    })?;
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(format!("{} holds no certificate", path.display()));
    }
    Ok(ureq::tls::RootCerts::new_with_certs(&certs))
}

fn http_agent(ca_file: Option<&Path>) -> Res<ureq::Agent> {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(trust_roots(ca_file)?)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build();
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        // Errors are answers here: they carry the reason and a fresh nonce.
        .http_status_as_error(false)
        .timeout_global(Some(HTTP_TIMEOUT))
        .user_agent(concat!("oxpanel-acme/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent())
}

impl Client {
    fn take(&mut self, response: ureq::http::Response<ureq::Body>) -> Res<Reply> {
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        if let Some(nonce) = header("replay-nonce") {
            self.nonce = Some(nonce);
        }
        let (status, location) = (response.status().as_u16(), header("location"));
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| format!("cannot read the authority's answer: {e}"))?;
        Ok(Reply {
            status,
            location,
            body,
        })
    }

    fn get(&mut self, url: &str) -> Res<Reply> {
        let response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?;
        self.take(response)
    }

    /// A signed POST; `payload` `None` is a POST-as-GET. A request the
    /// authority refuses because its nonce went stale is repeated with the
    /// fresh nonce that came with the refusal.
    fn post(&mut self, url: &str, payload: Option<&Value>) -> Res<Reply> {
        for _ in 0..NONCE_RETRIES {
            let nonce = if let Some(n) = self.nonce.take() {
                n
            } else {
                let new_nonce = self.new_nonce.clone();
                self.get(&new_nonce)?;
                self.nonce
                    .take()
                    .ok_or("the authority handed out no nonce")?
            };
            let body = self
                .account
                .sign(url, &nonce, self.kid.as_deref(), payload)?;
            let response = self
                .agent
                .post(url)
                .content_type("application/jose+json")
                .send(body.as_str())
                .map_err(|e| format!("{url}: {e}"))?;
            let reply = self.take(response)?;
            if reply.status == 400 && reply.body.contains("urn:ietf:params:acme:error:badNonce") {
                continue;
            }
            if reply.status >= 400 {
                return Err(format!(
                    "the authority refused ({}): {}",
                    reply.status,
                    problem(&reply.body)
                ));
            }
            return Ok(reply);
        }
        Err("the authority kept refusing our nonces".into())
    }

    /// Fetch `url` until its `status` is one of `done`, and return it.
    fn poll(&mut self, url: &str, what: &str, done: &[&str]) -> Res<Value> {
        for attempt in 0..POLL_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(POLL_INTERVAL);
            }
            let object = self.post(url, None)?.json()?;
            let status = required(&object, "status", what)?;
            if done.contains(&status) {
                return Ok(object);
            }
            if status == "invalid" {
                return Err(format!("the {what} failed: {}", failure_of(&object)));
            }
        }
        Err(format!("the {what} did not complete in time"))
    }
}

/// Why an authorization or order became invalid, in the authority's words.
fn failure_of(object: &Value) -> String {
    let from_challenges = object
        .get("challenges")
        .and_then(Value::as_array)
        .and_then(|cs| cs.iter().find_map(|c| c.get("error")));
    match from_challenges.or_else(|| object.get("error")) {
        Some(error) => problem(&error.to_string()),
        None => "no reason given".to_owned(),
    }
}

/// Removes the challenge files it was told about when it goes out of scope,
/// however the run ends.
struct Challenges {
    dir: PathBuf,
    tokens: Vec<String>,
}

impl Challenges {
    /// Publish `<token>.<thumbprint>` as `<dir>/<token>`.
    fn publish(&mut self, token: &str, thumbprint: &str) -> Res<()> {
        if !valid_token(token) {
            return Err("the authority sent a challenge token that is not base64url".into());
        }
        let path = self.dir.join(token);
        // A leftover of an earlier run; never follow whatever is there.
        let _ = std::fs::remove_file(&path);
        self.tokens.push(token.to_owned());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        file.write_all(format!("{token}.{thumbprint}").as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

impl Drop for Challenges {
    fn drop(&mut self) {
        for token in &self.tokens {
            let _ = std::fs::remove_file(self.dir.join(token));
        }
    }
}

/// Prove control of the name behind one authorization.
fn authorize(client: &mut Client, challenges: &mut Challenges, url: &str) -> Res<()> {
    let authz = client.post(url, None)?.json()?;
    let name = authz
        .get("identifier")
        .and_then(|i| text(i, "value"))
        .unwrap_or("?")
        .to_owned();
    if text(&authz, "status") == Some("valid") {
        eprintln!("{name}: already authorized");
        return Ok(());
    }
    let challenge = authz
        .get("challenges")
        .and_then(Value::as_array)
        .and_then(|cs| cs.iter().find(|c| text(c, "type") == Some("http-01")))
        .ok_or_else(|| format!("{name}: the authority offers no http-01 challenge"))?;
    let token = required(challenge, "token", "challenge")?;
    let challenge_url = required(challenge, "url", "challenge")?;
    challenges.publish(token, &client.account.thumbprint)?;
    client.post(challenge_url, Some(&json!({})))?;
    client
        .poll(url, "authorization", &["valid"])
        .map_err(|e| format!("{name}: {e}"))?;
    eprintln!("{name}: authorized");
    Ok(())
}

/// Write the chain next to its destination and rename it into place, so the
/// daemon never reads half a file.
fn deliver(out: &Path, chain: &str) -> Res<()> {
    let tmp = out.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| f.write_all(chain.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, out));
    written.map_err(|e| format!("cannot write {}: {e}", out.display()))
}

fn run(args: &Args) -> Res<()> {
    let csr = std::fs::read_to_string(&args.csr)
        .map_err(|e| format!("cannot read {}: {e}", args.csr.display()))?;
    let csr = pem_to_der(&csr)?;
    let agent = http_agent(args.ca_file.as_deref())?;
    let account = Account::load_or_create(&args.account_dir, &args.directory)?;
    let mut client = Client {
        agent,
        account,
        new_nonce: String::new(),
        nonce: None,
        kid: None,
    };
    let directory = client.get(&args.directory)?;
    if directory.status != 200 {
        return Err(format!("{} answered {}", args.directory, directory.status));
    }
    let directory = directory.json()?;
    required(&directory, "newNonce", "directory")?.clone_into(&mut client.new_nonce);
    let new_account = required(&directory, "newAccount", "directory")?.to_owned();
    let new_order = required(&directory, "newOrder", "directory")?.to_owned();

    // Registering again with the same key returns the existing account.
    let mut registration = json!({"termsOfServiceAgreed": true});
    if let (Some(email), Some(r)) = (&args.email, registration.as_object_mut()) {
        r.insert("contact".into(), json!([format!("mailto:{email}")]));
    }
    let registered = client.post(&new_account, Some(&registration))?;
    client.kid = Some(
        registered
            .location
            .ok_or("the authority did not name our account")?,
    );

    let identifiers: Vec<Value> = args
        .domains
        .iter()
        .map(|d| json!({"type": "dns", "value": d}))
        .collect();
    let ordered = client.post(&new_order, Some(&json!({"identifiers": identifiers})))?;
    let order_url = ordered
        .location
        .clone()
        .ok_or("the authority did not name our order")?;
    let order = ordered.json()?;
    eprintln!("ordered a certificate for {}", args.domains.join(", "));

    let mut challenges = Challenges {
        dir: args.challenge_dir.clone(),
        tokens: Vec::new(),
    };
    for authz in order
        .get("authorizations")
        .and_then(Value::as_array)
        .ok_or("the authority's order lists no authorizations")?
    {
        let url = authz.as_str().ok_or("an authorization is not a URL")?;
        authorize(&mut client, &mut challenges, url)?;
    }
    drop(challenges);

    let finalize = required(&order, "finalize", "order")?;
    client.post(finalize, Some(&json!({"csr": b64url(&csr)})))?;
    let order = client.poll(&order_url, "order", &["valid"])?;
    let certificate = required(&order, "certificate", "order")?;
    let chain = client.post(certificate, None)?.body;
    if !chain.contains("-----BEGIN CERTIFICATE-----") {
        return Err("the authority's answer holds no certificate".into());
    }
    deliver(&args.out, &chain)?;
    eprintln!("certificate issued");
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("no certificate: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    fn argv(s: &str) -> impl Iterator<Item = String> + '_ {
        s.split_whitespace().map(str::to_owned)
    }

    #[test]
    fn arguments_are_parsed_and_required() {
        let a = parse_args(argv(
            "--directory https://ca.example/dir --email ops@example.com --account-dir /a \
             --challenge-dir /c --csr /r.csr --out /o.pem --domain example.com --domain www.example.com",
        ))
        .unwrap();
        assert_eq!(a.directory, "https://ca.example/dir");
        assert_eq!(a.email.as_deref(), Some("ops@example.com"));
        assert_eq!(a.domains, vec!["example.com", "www.example.com"]);
        assert_eq!(a.ca_file, None);
        for bad in [
            "",
            "--directory https://ca.example/dir",
            "--directory http://ca.example/dir --account-dir /a --challenge-dir /c --csr /r --out /o --domain x.test",
            "--directory https://ca.example/dir --account-dir /a --challenge-dir /c --csr /r --out /o",
            "--directory https://ca.example/dir --bogus 1",
            "--directory",
        ] {
            assert!(parse_args(argv(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens_cannot_name_other_files() {
        assert!(valid_token("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"));
        assert!(valid_token("a-b_c"));
        for bad in ["", "../etc/passwd", "a/b", "a.b", "a b", "a\n"] {
            assert!(!valid_token(bad), "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let mut challenges = Challenges {
            dir: dir.path().to_owned(),
            tokens: Vec::new(),
        };
        assert!(challenges.publish("../escape", "thumb").is_err());
        challenges.publish("tok_1", "thumb").unwrap();
        let file = dir.path().join("tok_1");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "tok_1.thumb");
        // Published again (a retry): replaced, not followed.
        challenges.publish("tok_1", "thumb2").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "tok_1.thumb2");
        drop(challenges);
        assert!(!file.exists(), "challenge files are removed afterwards");
    }

    #[test]
    fn signing_requests_are_decoded_from_pem() {
        let pem = "junk\n-----BEGIN CERTIFICATE REQUEST-----\nAQID\nBAU=\n-----END CERTIFICATE REQUEST-----\n";
        assert_eq!(pem_to_der(pem).unwrap(), vec![1, 2, 3, 4, 5]);
        assert!(pem_to_der("not pem").is_err());
        assert!(pem_to_der("-----BEGIN X-----\n!!!\n-----END X-----\n").is_err());
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn account_key_persists_and_signs_verifiable_requests() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://ca.example/dir";
        let first = Account::load_or_create(dir.path(), url).unwrap();
        let again = Account::load_or_create(dir.path(), url).unwrap();
        assert_eq!(first.thumbprint, again.thumbprint, "the key is reused");
        let other = Account::load_or_create(dir.path(), "https://staging.example/dir").unwrap();
        assert_ne!(first.thumbprint, other.thumbprint, "one key per directory");
        let key_file = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let mode = std::os::unix::fs::MetadataExt::mode(&key_file.metadata().unwrap());
        assert_eq!(mode & 0o777, 0o600, "the account key is private");

        // First request of an account: the key itself is in the header.
        let jws: Value = serde_json::from_str(
            &first
                .sign(
                    "https://ca.example/new-acct",
                    "nonce-1",
                    None,
                    Some(&json!({"a": 1})),
                )
                .unwrap(),
        )
        .unwrap();
        let protected = text(&jws, "protected").unwrap();
        let payload = text(&jws, "payload").unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(text(&header, "alg"), Some("ES256"));
        assert_eq!(text(&header, "nonce"), Some("nonce-1"));
        assert_eq!(text(&header, "url"), Some("https://ca.example/new-acct"));
        assert_eq!(header.get("jwk"), Some(&first.jwk));
        assert!(header.get("kid").is_none());
        assert_eq!(URL_SAFE_NO_PAD.decode(payload).unwrap(), br#"{"a":1}"#);
        let signature = URL_SAFE_NO_PAD
            .decode(text(&jws, "signature").unwrap())
            .unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, first.key.public_key().as_ref())
            .verify(format!("{protected}.{payload}").as_bytes(), &signature)
            .unwrap();

        // Later requests name the account; a POST-as-GET has an empty payload.
        let jws: Value = serde_json::from_str(
            &first
                .sign(
                    "https://ca.example/order/1",
                    "nonce-2",
                    Some("https://ca.example/acct/7"),
                    None,
                )
                .unwrap(),
        )
        .unwrap();
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(text(&jws, "protected").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(text(&header, "kid"), Some("https://ca.example/acct/7"));
        assert!(header.get("jwk").is_none());
        assert_eq!(text(&jws, "payload"), Some(""));
    }

    #[test]
    fn problems_are_reported_in_the_authoritys_words() {
        assert_eq!(
            problem(
                r#"{"type":"urn:ietf:params:acme:error:dns","detail":"NXDOMAIN looking up A for x.test"}"#
            ),
            "NXDOMAIN looking up A for x.test (urn:ietf:params:acme:error:dns)"
        );
        assert_eq!(problem("plain text"), "plain text");
        let authz = json!({"status": "invalid", "challenges": [
            {"type": "dns-01"},
            {"type": "http-01", "error": {"type": "urn:x", "detail": "connection refused"}}
        ]});
        assert_eq!(failure_of(&authz), "connection refused (urn:x)");
        assert_eq!(failure_of(&json!({"status": "invalid"})), "no reason given");
    }
}
