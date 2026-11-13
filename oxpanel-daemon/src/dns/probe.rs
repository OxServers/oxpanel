//! Looking at the DNS from outside the daemon.
//!
//! The daemon has no network (`PrivateNetwork=yes`), but three things can
//! only be learnt from the network: whether a domain is delegated to this
//! host's name servers, whether its parent publishes a DS record, and which
//! serial each name server (this one and the secondaries) serves. They are
//! asked by `oxpanel-daemon dns-probe`, the daemon's own binary in probe
//! mode, run in a transient unit under a dynamic, unprivileged user with no
//! capabilities and nothing writable; it prints one line per question to a
//! root-only file the daemon reads back. It sends plain queries (UDP, TCP if
//! the answer is truncated) and parses answers with [`super::wire`].
//!
//! Questions are `server name type rd`, where `server` is `resolver` (the
//! configured check resolver, else the first `nameserver` of
//! `/etc/resolv.conf`) or an address with port. Answer lines:
//! `<i> ok <rcode> <aa 0|1> [soa=<serial>] [ns=<name>]… [ds=<tag>/<alg>/<type>/<hex>]…`
//! or `<i> fail <reason>`.

use std::fmt::Write as _;
use std::io::{Read as _, Write as IoWrite};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use super::wire::{self, Data};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::fsutil;
use crate::nginx::safe_path_str;
use crate::system::{bin, CommandSpec};

pub const SUBCOMMAND: &str = "dns-probe";
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const TRIES: usize = 2;
const PARALLEL: usize = 16;
/// How the probe's unit is bounded as a whole.
const UNIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Where a question is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Server {
    Resolver,
    At(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub server: Server,
    /// Absolute, without the final dot.
    pub name: String,
    pub qtype: u16,
    pub recursion: bool,
}

/// What a server answered (only records owned by the name asked for).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub rcode: u8,
    pub authoritative: bool,
    pub soa_serial: Option<u32>,
    pub ns: Vec<String>,
    /// `tag/alg/type/HEX`.
    pub ds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Answer(Answer),
    Failed(String),
}

fn type_name(t: u16) -> &'static str {
    match t {
        wire::TYPE_NS => "NS",
        wire::TYPE_SOA => "SOA",
        wire::TYPE_DS => "DS",
        _ => "?",
    }
}

fn type_from(s: &str) -> Option<u16> {
    match s {
        "NS" => Some(wire::TYPE_NS),
        "SOA" => Some(wire::TYPE_SOA),
        "DS" => Some(wire::TYPE_DS),
        _ => None,
    }
}

/// Run the probe for `questions` and return one outcome per question.
pub async fn run(ctx: &Ctx, questions: &[Question]) -> Result<Vec<Outcome>> {
    if questions.is_empty() {
        return Ok(Vec::new());
    }
    let cfg = &ctx.config;
    let out = super::bind::scratch_file(cfg, "dns-probe")?;
    let mut cmd = CommandSpec::new(bin::SYSTEMD_RUN, UNIT_TIMEOUT)
        .args(["--wait", "--collect", "--quiet"])
        .arg(format!(
            "--property=StandardOutput=truncate:{}",
            safe_path_str(&out)?
        ));
    for p in [
        "DynamicUser=yes",
        "CapabilityBoundingSet=",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "RestrictNamespaces=yes",
        "MemoryDenyWriteExecute=yes",
        "RuntimeMaxSec=100",
    ] {
        cmd = cmd.arg(format!("--property={p}"));
    }
    cmd = cmd.arg("--").arg(&cfg.worker_exe).arg(SUBCOMMAND);
    if let Some(r) = cfg.dns.check_resolver {
        cmd = cmd.arg("--resolver").arg(r.to_string());
    }
    for q in questions {
        let server = match &q.server {
            Server::Resolver => "resolver".to_owned(),
            Server::At(sa) => sa.to_string(),
        };
        cmd = cmd
            .arg("--q")
            .arg(server)
            .arg(&q.name)
            .arg(type_name(q.qtype))
            .arg(if q.recursion { "1" } else { "0" });
    }
    let result = ctx.sys.run(cmd).await;
    let text = fsutil::read_optional(&out);
    fsutil::remove_if_exists(&out)?;
    let output = result?;
    let text = String::from_utf8_lossy(&text?.unwrap_or_default()).into_owned();
    if !output.success() && text.trim().is_empty() {
        return Err(Error::Internal(format!(
            "the DNS probe did not run: {}",
            output.combined_lossy()
        )));
    }
    Ok(parse_output(&text, questions.len()))
}

/// Read the probe's lines; a question without a line failed.
pub fn parse_output(text: &str, n: usize) -> Vec<Outcome> {
    let mut out = vec![Outcome::Failed("no answer from the probe".to_owned()); n];
    for line in text.lines() {
        let mut f = line.split(' ');
        let Some(i) = f.next().and_then(|i| i.parse::<usize>().ok()) else {
            continue;
        };
        let Some(slot) = out.get_mut(i) else { continue };
        match f.next() {
            Some("fail") => *slot = Outcome::Failed(f.collect::<Vec<_>>().join(" ")),
            Some("ok") => {
                let mut a = Answer {
                    rcode: match f.next() {
                        Some("NOERROR") => 0,
                        Some("SERVFAIL") => 2,
                        Some("NXDOMAIN") => 3,
                        Some("REFUSED") => 5,
                        _ => 255,
                    },
                    authoritative: f.next() == Some("1"),
                    ..Answer::default()
                };
                for item in f {
                    if let Some(v) = item.strip_prefix("soa=") {
                        a.soa_serial = v.parse().ok();
                    } else if let Some(v) = item.strip_prefix("ns=") {
                        a.ns.push(v.to_owned());
                    } else if let Some(v) = item.strip_prefix("ds=") {
                        a.ds.push(v.to_owned());
                    }
                }
                *slot = Outcome::Answer(a);
            }
            _ => {}
        }
    }
    out
}

// ---- the probe process ---------------------------------------------------

/// Parse the probe's arguments (after the program name).
fn parse_args(args: &[String]) -> std::result::Result<(Option<SocketAddr>, Vec<Question>), String> {
    let mut it = args.iter().skip(1);
    let mut resolver = None;
    let mut questions = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--resolver" => {
                let v = it.next().ok_or("--resolver needs an address")?;
                resolver = Some(v.parse().map_err(|_| format!("bad resolver {v}"))?);
            }
            "--q" => {
                let (Some(s), Some(n), Some(t), Some(rd)) =
                    (it.next(), it.next(), it.next(), it.next())
                else {
                    return Err("--q needs server name type rd".to_owned());
                };
                let server = if s == "resolver" {
                    Server::Resolver
                } else {
                    Server::At(s.parse().map_err(|_| format!("bad server {s}"))?)
                };
                questions.push(Question {
                    server,
                    name: n.clone(),
                    qtype: type_from(t).ok_or_else(|| format!("bad type {t}"))?,
                    recursion: rd == "1",
                });
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok((resolver, questions))
}

/// The first `nameserver` of `/etc/resolv.conf`.
fn system_resolver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string(PathBuf::from("/etc/resolv.conf")).ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next() == Some("nameserver"))
            .then(|| f.next())
            .flatten()
            .and_then(|a| super::config::parse_server("resolv.conf", a).ok())
    })
}

fn exchange(server: SocketAddr, query: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let mut last = String::from("no answer");
    for _ in 0..TRIES {
        let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(QUERY_TIMEOUT))
            .map_err(|e| e.to_string())?;
        sock.connect(server).map_err(|e| e.to_string())?;
        sock.send(query).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

fn exchange_tcp(server: SocketAddr, query: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut s = TcpStream::connect_timeout(&server, QUERY_TIMEOUT).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(QUERY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let len = u16::try_from(query.len()).map_err(|_| "query too long".to_owned())?;
    let mut msg = len.to_be_bytes().to_vec();
    msg.extend_from_slice(query);
    s.write_all(&msg).map_err(|e| e.to_string())?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lb))];
    s.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Ask one question; the answer line without the index.
fn ask(q: &Question, resolver: Option<SocketAddr>, id: u16) -> String {
    let server = match &q.server {
        Server::At(sa) => *sa,
        Server::Resolver => match resolver {
            Some(r) => r,
            None => {
                return "fail no resolver configured (no nameserver in /etc/resolv.conf)".to_owned()
            }
        },
    };
    let query = match wire::encode_query(id, &q.name, q.qtype, q.recursion) {
        Ok(q) => q,
        Err(e) => return format!("fail {}", e.0),
    };
    let mut bytes = match exchange(server, &query) {
        Ok(b) => b,
        Err(e) => return format!("fail no answer from {server}: {e}"),
    };
    let mut resp = match wire::decode(&bytes) {
        Ok(r) => r,
        Err(e) => return format!("fail bad answer from {server}: {}", e.0),
    };
    if resp.truncated {
        bytes = match exchange_tcp(server, &query) {
            Ok(b) => b,
            Err(e) => return format!("fail no answer over TCP from {server}: {e}"),
        };
        resp = match wire::decode(&bytes) {
            Ok(r) => r,
            Err(e) => return format!("fail bad answer from {server}: {}", e.0),
        };
    }
    if resp.id != id {
        return format!("fail answer from {server} does not match the question");
    }
    let mut line = format!(
        "ok {} {}",
        wire::rcode_name(resp.rcode),
        u8::from(resp.authoritative)
    );
    let name = q.name.to_ascii_lowercase();
    for r in resp.answers.iter().filter(|r| r.name == name) {
        match &r.data {
            Data::Soa { serial } if q.qtype == wire::TYPE_SOA => {
                let _ = write!(line, " soa={serial}");
            }
            Data::Ns(n) if q.qtype == wire::TYPE_NS => {
                let _ = write!(line, " ns={n}");
            }
            Data::Ds(tag, alg, dt, hex) if q.qtype == wire::TYPE_DS => {
                let _ = write!(line, " ds={tag}/{alg}/{dt}/{hex}");
            }
            _ => {}
        }
    }
    line
}

/// `oxpanel-daemon dns-probe …`: answer every question, print the lines,
/// exit 0 (failures are lines too) or 2 on bad arguments.
pub fn main(args: &[String]) -> u8 {
    let (resolver, questions) = match parse_args(args) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "dns-probe: {e}");
            return 2;
        }
    };
    let resolver = resolver.or_else(system_resolver);
    let seed = u16::try_from(std::process::id() & 0xffff).unwrap_or(1);
    let mut lines: Vec<String> = Vec::with_capacity(questions.len());
    for (chunk_no, chunk) in questions.chunks(PARALLEL).enumerate() {
        let handles: Vec<_> = chunk
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let q = q.clone();
                let id = seed.wrapping_add(u16::try_from(chunk_no * PARALLEL + i).unwrap_or(0));
                std::thread::spawn(move || ask(&q, resolver, id))
            })
            .collect();
        for h in handles {
            lines.push(
                h.join()
                    .unwrap_or_else(|_| "fail probe thread failed".to_owned()),
            );
        }
    }
    let mut out = std::io::stdout().lock();
    for (i, l) in lines.iter().enumerate() {
        let _ = writeln!(out, "{i} {l}");
    }
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn arguments_and_output_round_trip() {
        let args: Vec<String> = [
            "dns-probe",
            "--resolver",
            "127.0.0.1:853",
            "--q",
            "resolver",
            "example.com",
            "NS",
            "1",
            "--q",
            "127.0.0.1:53",
            "example.com",
            "SOA",
            "0",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let (r, q) = parse_args(&args).unwrap();
        assert_eq!(r, Some("127.0.0.1:853".parse().unwrap()));
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].server, Server::Resolver);
        assert!(q[0].recursion);
        assert_eq!(q[1].qtype, wire::TYPE_SOA);
        let out = parse_output(
            "0 ok NOERROR 0 ns=ns1.example.net ns=ns2.example.net\n1 fail no answer from 127.0.0.1:53: timed out\nnoise\n9 ok NOERROR 1 soa=5\n",
            3,
        );
        assert_eq!(
            out[0],
            Outcome::Answer(Answer {
                rcode: 0,
                authoritative: false,
                soa_serial: None,
                ns: vec!["ns1.example.net".into(), "ns2.example.net".into()],
                ds: vec![],
            })
        );
        assert!(matches!(&out[1], Outcome::Failed(m) if m.contains("timed out")));
        assert!(
            matches!(&out[2], Outcome::Failed(_)),
            "missing line = failed"
        );
        assert!(parse_args(&["dns-probe".into(), "--q".into()]).is_err());
        assert!(parse_args(&["dns-probe".into(), "--evil".into()]).is_err());
    }

    #[test]
    fn a_question_to_nobody_fails_cleanly() {
        let q = Question {
            server: Server::Resolver,
            name: "example.com".into(),
            qtype: wire::TYPE_NS,
            recursion: true,
        };
        assert!(ask(&q, None, 1).starts_with("fail no resolver"));
    }
}
