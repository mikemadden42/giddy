//! Just enough DNS wire format for mDNS discovery.

use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;

/// A domain name as its raw labels (instance names may contain dots or
/// arbitrary UTF-8, so we never round-trip through presentation format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(pub Vec<String>);

impl Name {
    pub fn parse(s: &str) -> Self {
        Name(s.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).map(String::from).collect())
    }

    /// Lowercased dotted form, for use as a map key.
    pub fn key(&self) -> String {
        self.0.join(".").to_ascii_lowercase()
    }

    /// Dotted form without a trailing `.local`.
    pub fn host(&self) -> String {
        let labels = match self.0.last() {
            Some(l) if l.eq_ignore_ascii_case("local") => &self.0[..self.0.len() - 1],
            _ => &self.0[..],
        };
        labels.join(".")
    }

    /// Split `Instance._svc._tcp.local` into (`Instance`, `_svc._tcp`).
    pub fn split_instance(&self) -> Option<(String, String)> {
        let n = self.0.len();
        if n < 4 || !self.0[n - 1].eq_ignore_ascii_case("local") {
            return None;
        }
        let proto = &self.0[n - 2];
        let svc = &self.0[n - 3];
        if !svc.starts_with('_') || !(proto == "_tcp" || proto == "_udp") {
            return None;
        }
        // Instance is everything before the service type (normally a single label).
        Some((self.0[..n - 3].join("."), format!("{svc}.{proto}")))
    }
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Ptr(Name),
    Srv { target: Name },
    Txt(Vec<String>),
    Other,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: Name,
    pub data: RData,
}

/// Build a query with the given questions. `unicast` sets the mDNS QU bit,
/// asking responders to reply directly to us.
pub fn build_query(questions: &[(Name, u16)], unicast: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&[0, 0, 0, 0]); // id, flags
    let count = u16::try_from(questions.len()).expect("callers batch questions well under 65535");
    buf.extend_from_slice(&count.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an, ns, ar counts
    for (name, qtype) in questions {
        for label in &name.0 {
            // DNS labels are at most 63 bytes.
            let len = u8::try_from(label.len()).unwrap_or(u8::MAX).min(63);
            buf.push(len);
            buf.extend_from_slice(&label.as_bytes()[..usize::from(len)]);
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        let class: u16 = if unicast { 0x8001 } else { 0x0001 };
        buf.extend_from_slice(&class.to_be_bytes());
    }
    buf
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(b)
    }

    /// Read a possibly-compressed name, leaving `pos` just past it.
    fn name(&mut self) -> Option<Name> {
        let mut labels = Vec::new();
        let mut pos = self.pos;
        let mut resume = None;
        let mut jumps = 0;
        loop {
            let len = *self.buf.get(pos)? as usize;
            match len & 0xc0 {
                0x00 if len == 0 => {
                    pos += 1;
                    break;
                }
                0x00 => {
                    let label = self.buf.get(pos + 1..pos + 1 + len)?;
                    labels.push(String::from_utf8_lossy(label).into_owned());
                    pos += 1 + len;
                }
                0xc0 => {
                    let lo = *self.buf.get(pos + 1)? as usize;
                    resume.get_or_insert(pos + 2);
                    pos = ((len & 0x3f) << 8) | lo;
                    jumps += 1;
                    if jumps > 32 {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        self.pos = resume.unwrap_or(pos);
        Some(Name(labels))
    }
}

/// Parse a response, returning every resource record from the answer,
/// authority and additional sections. Returns `None` for queries or garbage.
pub fn parse_response(buf: &[u8]) -> Option<Vec<Record>> {
    let mut r = Reader { buf, pos: 0 };
    let _id = r.u16()?;
    let flags = r.u16()?;
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    let qd = r.u16()?;
    let counts = [r.u16()?, r.u16()?, r.u16()?];
    for _ in 0..qd {
        r.name()?;
        r.u32()?; // type + class
    }
    let total: usize = counts.iter().map(|c| *c as usize).sum();
    let mut records = Vec::with_capacity(total);
    for _ in 0..total {
        let name = r.name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let _ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let end = start + rdlen;
        if end > buf.len() {
            return None;
        }
        let data = match rtype {
            TYPE_A if rdlen == 4 => {
                let b = r.bytes(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            TYPE_PTR => RData::Ptr(r.name()?),
            TYPE_SRV => {
                let _prio = r.u16()?;
                let _weight = r.u16()?;
                let _port = r.u16()?;
                RData::Srv { target: r.name()? }
            }
            TYPE_TXT => {
                let mut strings = Vec::new();
                while r.pos < end {
                    let len = r.u8()? as usize;
                    let s = r.bytes(len.min(end.saturating_sub(r.pos)))?;
                    if !s.is_empty() {
                        strings.push(String::from_utf8_lossy(s).into_owned());
                    }
                }
                RData::Txt(strings)
            }
            _ => RData::Other,
        };
        r.pos = end;
        records.push(Record { name, data });
    }
    Some(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = build_query(&[(Name::parse("_http._tcp.local"), TYPE_PTR)], true);
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(&q[12..18], b"\x05_http");
        assert_eq!(&q[q.len() - 4..], &[0, 12, 0x80, 0x01]);
    }

    #[test]
    fn parse_compressed_response() {
        // Response: 1 answer PTR _http._tcp.local -> "My Printer"._http._tcp.local,
        // 1 additional A printer.local -> 10.0.0.72
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        // offset 12: _http._tcp.local
        b.extend_from_slice(b"\x05_http\x04_tcp\x05local\x00");
        b.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120]);
        let rdata: Vec<u8> = [&b"\x0aMy Printer"[..], &[0xc0, 12]].concat();
        b.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&rdata);
        b.extend_from_slice(b"\x07printer");
        b.extend_from_slice(&[0xc0, 23]); // -> "local"
        b.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 72]);

        let recs = parse_response(&b).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].name.key(), "_http._tcp.local");
        let RData::Ptr(target) = &recs[0].data else { panic!() };
        assert_eq!(target.split_instance(), Some(("My Printer".into(), "_http._tcp".into())));
        assert_eq!(recs[1].name.host(), "printer");
        assert!(matches!(recs[1].data, RData::A(ip) if ip == Ipv4Addr::new(10, 0, 0, 72)));
    }

    #[test]
    fn pointer_loops_are_rejected() {
        let b = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12];
        assert!(parse_response(&b).is_none());
    }
}
