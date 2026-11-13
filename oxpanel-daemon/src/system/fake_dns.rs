//! The DNS server on the fake host: `named -v`, the checkers (which accept
//! everything unless a test scripts a failure), `rndc` and the `systemctl`
//! verbs for `oxpanel-dns.service` (which "load" the serials of the zone
//! files), and the DNS probe (which answers from what was loaded, and from
//! answers the tests give the resolver).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::{bin, CommandOutput, CommandSpec};

#[derive(Debug, Default)]
pub(crate) struct FakeDns {
    /// Where the zone files are; the fake server reads their serials.
    pub zones_dir: Option<PathBuf>,
    /// Serial the fake primary serves, per zone.
    pub served: BTreeMap<String, u32>,
    /// The server is stopped.
    pub down: bool,
    /// Secondaries serve one serial less than the primary.
    pub secondaries_lag: bool,
    /// Answer lines (after the index) the resolver gives, per (name, type).
    pub resolver: BTreeMap<(String, String), String>,
}

fn out(program: &'static str, code: i32, stdout: &str) -> CommandOutput {
    CommandOutput {
        program,
        code: Some(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// The SOA serial in a zone file.
fn file_serial(path: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let at = f.iter().position(|w| *w == "SOA")?;
        f.get(at + 3)?.parse().ok()
    })
}

impl FakeDns {
    /// What a start or `reconfig` does: zones with a file that are not
    /// served yet are loaded, zones without a file are dropped.
    fn load_all(&mut self) {
        let Some(dir) = self.zones_dir.clone() else {
            return;
        };
        let mut served = BTreeMap::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(zone) = name.strip_suffix(".zone") {
                    let serial = self
                        .served
                        .get(zone)
                        .copied()
                        .or_else(|| file_serial(&e.path()));
                    if let Some(s) = serial {
                        served.insert(zone.to_owned(), s);
                    }
                }
            }
        }
        self.served = served;
    }

    fn reload(&mut self, zone: &str) {
        if let Some(dir) = &self.zones_dir {
            if let Some(s) = file_serial(&dir.join(format!("{zone}.zone"))) {
                self.served.insert(zone.to_owned(), s);
            }
        }
    }

    fn answer(&self, server: &str, name: &str, qtype: &str) -> String {
        if server == "resolver" {
            return self
                .resolver
                .get(&(name.to_owned(), qtype.to_owned()))
                .cloned()
                .unwrap_or_else(|| "fail no answer from 192.0.2.53:53: timed out".to_owned());
        }
        let primary = server == "127.0.0.1:53";
        if self.down && primary {
            return format!("fail no answer from {server}: connection refused");
        }
        match self.served.get(name) {
            Some(s) if qtype == "SOA" => {
                let s = if !primary && self.secondaries_lag {
                    s.wrapping_sub(1)
                } else {
                    *s
                };
                format!("ok NOERROR 1 soa={s}")
            }
            _ => "ok REFUSED 0".to_owned(),
        }
    }

    fn probe(&self, args: &[String]) -> String {
        let mut lines = String::new();
        let starts = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--q")
            .map(|(i, _)| i);
        for (n, at) in starts.enumerate() {
            let field = |k: usize| args.get(at + k).map_or("", String::as_str);
            let _ = writeln!(lines, "{n} {}", self.answer(field(1), field(2), field(3)));
        }
        lines
    }
}

/// The output file a transient unit's standard output goes to.
fn stdout_file(args: &[String]) -> Option<&str> {
    args.iter()
        .find_map(|a| a.strip_prefix("--property=StandardOutput=truncate:"))
}

/// Commands of DNS hosting; `None` for anything else.
pub(crate) fn command(dns: &mut FakeDns, spec: &CommandSpec) -> Option<CommandOutput> {
    let program = spec.program;
    let args = strings(&spec.args);
    let has = |s: &str| args.iter().any(|a| a == s);
    let our_unit = has(crate::dns::bind::SERVICE);
    Some(match program {
        bin::NAMED => out(
            program,
            0,
            "BIND 9.16.23-RH (Extended Support Version) <id:fde3b1f>\n",
        ),
        bin::NAMED_CHECKCONF => out(program, 0, ""),
        bin::NAMED_CHECKZONE => out(program, 0, "zone loaded\nOK\n"),
        bin::SYSTEMCTL if has("is-active") && has(crate::dns::bind::STOCK_SERVICE) => {
            out(program, 3, "")
        }
        bin::SYSTEMCTL if has("is-active") && our_unit => out(program, i32::from(dns.down) * 3, ""),
        bin::SYSTEMCTL if (has("enable") || has("start")) && our_unit => {
            dns.down = false;
            dns.load_all();
            out(program, 0, "")
        }
        bin::SYSTEMCTL if has("reload") && our_unit => {
            if dns.down {
                return Some(out(program, 1, ""));
            }
            dns.load_all();
            out(program, 0, "")
        }
        bin::SYSTEMD_RUN if has(bin::RNDC) => {
            let text = if dns.down {
                "rndc: connect failed: 127.0.0.1#953: connection refused\n"
            } else {
                if let Some(zone) = args.iter().skip_while(|a| *a != "reload").nth(1) {
                    dns.reload(zone);
                }
                "zone reload queued\n"
            };
            if let Some(f) = stdout_file(&args) {
                let _ = std::fs::write(f, text);
            }
            out(program, i32::from(dns.down), "")
        }
        bin::SYSTEMD_RUN if has(crate::dns::probe::SUBCOMMAND) => {
            let text = dns.probe(&args);
            match stdout_file(&args).map(|f| std::fs::write(f, text)) {
                Some(Ok(())) => out(program, 0, ""),
                _ => out(program, 1, ""),
            }
        }
        _ => return None,
    })
}
