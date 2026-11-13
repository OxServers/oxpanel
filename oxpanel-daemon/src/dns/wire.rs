//! Just enough of the DNS wire format (RFC 1035) for the probe: build a
//! query, and read the answer and authority sections of a response for the
//! types the engine asks about (SOA, NS, DS, DNSKEY). Every read is bounds-
//! checked and compression pointers may only point backwards, so a hostile
//! or broken response is an error, never a panic or a loop.

use std::fmt::Write as _;

/// Query types the probe asks for.
pub const TYPE_NS: u16 = 2;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_DS: u16 = 43;
pub const TYPE_DNSKEY: u16 = 48;
const CLASS_IN: u16 = 1;
const HEADER: usize = 12;
const MAX_NAME: usize = 255;

/// Error while reading a message; the text is for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

type R<T> = std::result::Result<T, WireError>;

/// A query for `name` (absolute, without the final dot) of `qtype`.
pub fn encode_query(id: u16, name: &str, qtype: u16, recursion_desired: bool) -> R<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0, opcode 0, RD as asked.
    out.push(u8::from(recursion_desired));
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR
    if name.len() > MAX_NAME - 2 {
        return Err(WireError("name too long"));
    }
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = u8::try_from(label.len()).map_err(|_| WireError("label too long"))?;
        if len > 63 {
            return Err(WireError("label too long"));
        }
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// What a record of interest says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    Soa {
        serial: u32,
    },
    Ns(String),
    /// Key tag, algorithm, digest type, digest (upper-case hex).
    Ds(u16, u8, u8, String),
    /// Flags, protocol, algorithm, public key.
    Dnskey(u16, u8, u8, Vec<u8>),
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Owner, lower case, without the final dot.
    pub name: String,
    pub data: Data,
}

/// The parts of a response the probe uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> R<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(WireError("truncated message"))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> R<u16> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    fn u32(&mut self) -> R<u32> {
        Ok(u32::from_be_bytes([
            self.u8()?,
            self.u8()?,
            self.u8()?,
            self.u8()?,
        ]))
    }

    fn bytes(&mut self, n: usize) -> R<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(WireError("length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(WireError("truncated message"))?;
        self.pos = end;
        Ok(s)
    }

    /// A possibly compressed name starting at the current position.
    fn name(&mut self) -> R<String> {
        let (name, next) = read_name(self.buf, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

/// Read a name at `start`; returns it and the position after it (after the
/// first pointer, if compressed). Pointers must point strictly backwards.
fn read_name(buf: &[u8], start: usize) -> R<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut total = 0usize;
    loop {
        let len = *buf.get(pos).ok_or(WireError("truncated name"))?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let l = usize::from(len);
                let bytes = buf
                    .get(pos + 1..pos + 1 + l)
                    .ok_or(WireError("truncated label"))?;
                total += l + 1;
                if total > MAX_NAME {
                    return Err(WireError("name too long"));
                }
                labels.push(
                    bytes
                        .iter()
                        .map(|b| char::from(b.to_ascii_lowercase()))
                        .collect(),
                );
                pos += 1 + l;
            }
            0xc0 => {
                let lo = *buf.get(pos + 1).ok_or(WireError("truncated pointer"))?;
                let target = usize::from(u16::from_be_bytes([len & 0x3f, lo]));
                if target >= pos {
                    return Err(WireError("compression pointer does not point backwards"));
                }
                if after.is_none() {
                    after = Some(pos + 2);
                }
                pos = target;
            }
            _ => return Err(WireError("unsupported label type")),
        }
    }
    Ok((labels.join("."), after.unwrap_or(pos)))
}

/// Decode a response.
pub fn decode(buf: &[u8]) -> R<Response> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    if flags & 0x8000 == 0 {
        return Err(WireError("not a response"));
    }
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let _ar = r.u16()?;
    for _ in 0..qd {
        r.name()?;
        r.bytes(4)?;
    }
    let mut section = |count: u16| -> R<Vec<Record>> {
        let mut out = Vec::new();
        for _ in 0..count {
            let name = r.name()?;
            let rtype = r.u16()?;
            let _class = r.u16()?;
            let _ttl = r.u32()?;
            let len = usize::from(r.u16()?);
            let start = r.pos;
            let data = match rtype {
                TYPE_SOA => {
                    r.name()?;
                    r.name()?;
                    Data::Soa { serial: r.u32()? }
                }
                TYPE_NS => Data::Ns(r.name()?),
                TYPE_DS => {
                    if len < 4 {
                        return Err(WireError("short DS record"));
                    }
                    let tag = r.u16()?;
                    let alg = r.u8()?;
                    let dtype = r.u8()?;
                    let digest = r.bytes(len - 4)?;
                    Data::Ds(tag, alg, dtype, hex_upper(digest))
                }
                TYPE_DNSKEY => {
                    if len < 4 {
                        return Err(WireError("short DNSKEY record"));
                    }
                    let flags = r.u16()?;
                    let proto = r.u8()?;
                    let alg = r.u8()?;
                    Data::Dnskey(flags, proto, alg, r.bytes(len - 4)?.to_vec())
                }
                other => Data::Other(other),
            };
            // Whatever the data held, the next record starts after it.
            r.pos = start.checked_add(len).ok_or(WireError("length overflow"))?;
            if r.pos > buf.len() {
                return Err(WireError("truncated record"));
            }
            out.push(Record { name, data });
        }
        Ok(out)
    };
    let answers = section(an)?;
    let authority = section(ns)?;
    Ok(Response {
        id,
        rcode: u8::try_from(flags & 0x000f).unwrap_or(0),
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        answers,
        authority,
    })
}

pub fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// The name of a response code.
pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    /// A response for the tests: header, the question, then records given as
    /// (owner wire name, type, rdata).
    pub(crate) fn response(
        id: u16,
        flags: u16,
        question: &str,
        qtype: u16,
        answers: &[(Vec<u8>, u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut q = encode_query(id, question, qtype, false).unwrap();
        q[2..4].copy_from_slice(&flags.to_be_bytes());
        q[6..8].copy_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
        for (owner, t, rdata) in answers {
            q.extend_from_slice(owner);
            q.extend_from_slice(&t.to_be_bytes());
            q.extend_from_slice(&1u16.to_be_bytes());
            q.extend_from_slice(&3600u32.to_be_bytes());
            q.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            q.extend_from_slice(rdata);
        }
        q
    }

    pub(crate) fn wire_name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in n.split('.').filter(|l| !l.is_empty()) {
            out.push(u8::try_from(l.len()).unwrap());
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn queries_are_encoded_exactly() {
        let q = encode_query(0x1234, "example.com", TYPE_SOA, true).unwrap();
        assert_eq!(
            q,
            [
                0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 6, 0, 1
            ]
        );
        assert!(encode_query(1, &"a".repeat(64), TYPE_NS, false).is_err());
    }

    #[test]
    fn soa_ns_and_ds_answers_are_read() {
        let mut soa = wire_name("ns1.example.net");
        soa.extend(wire_name("hostmaster.example.net"));
        for v in [1_763_000_000u32, 7200, 3600, 1_209_600, 3600] {
            soa.extend_from_slice(&v.to_be_bytes());
        }
        // Owner as a compression pointer to the question name (offset 12).
        let ptr = vec![0xc0, 12];
        let mut ds = vec![0x72, 0xb3, 13, 2];
        ds.extend_from_slice(&[0xab; 32]);
        let msg = response(
            7,
            0x8400,
            "Example.COM",
            TYPE_SOA,
            &[
                (ptr.clone(), TYPE_SOA, soa),
                (ptr.clone(), TYPE_NS, wire_name("ns2.example.net")),
                (ptr, TYPE_DS, ds),
            ],
        );
        let r = decode(&msg).unwrap();
        assert_eq!(r.id, 7);
        assert!(r.authoritative);
        assert_eq!(r.rcode, 0);
        assert_eq!(r.answers[0].name, "example.com");
        assert_eq!(
            r.answers[0].data,
            Data::Soa {
                serial: 1_763_000_000
            }
        );
        assert_eq!(r.answers[1].data, Data::Ns("ns2.example.net".into()));
        assert_eq!(r.answers[2].data, Data::Ds(0x72b3, 13, 2, "AB".repeat(32)));
    }

    #[test]
    fn hostile_messages_are_errors() {
        // Pointer loop: points at itself.
        let mut msg = response(1, 0x8000, "a.b", TYPE_NS, &[]);
        msg[7] = 1; // one answer
        let here = u8::try_from(msg.len()).unwrap();
        msg.extend_from_slice(&[0xc0, here]);
        assert!(decode(&msg).is_err());
        // Truncated everywhere.
        let good = response(
            1,
            0x8000,
            "a.b",
            TYPE_NS,
            &[(wire_name("a.b"), TYPE_NS, wire_name("ns.c.d"))],
        );
        for cut in 0..good.len() {
            assert!(decode(&good[..cut]).is_err(), "cut at {cut}");
        }
        assert!(decode(&good).is_ok());
        // A query is not a response.
        assert!(decode(&encode_query(1, "a.b", TYPE_NS, false).unwrap()).is_err());
    }
}
