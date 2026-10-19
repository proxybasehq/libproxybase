//! Fake-IP DNS responder.
//!
//! Every `A` query is answered locally with an address from the RFC 2544
//! benchmarking range (`198.18.0.0/15`) and the mapping is kept in an LRU
//! cache. When the userspace TCP stack later sees a connection to that fake
//! address, [`crate::tunnel::engine`] reverses the mapping and sends the real
//! domain name to the SOCKS5 upstream (`ATYP = DOMAINNAME`), so DNS resolution
//! happens at the exit node's location with zero resolver leaks.
//!
//! `AAAA`/`HTTPS`/`SVCB` queries are answered `NOERROR` with an empty answer
//! section. That keeps dual-stack clients on the IPv4 fake range and prevents
//! browsers from reading `ipv4hint`/`ech` parameters that would bypass the
//! tunnel. All other query types are forwarded as DNS-over-TCP by the engine.

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// TTL is deliberately tiny. When the tunnel is torn down, browsers and the
/// OS resolver forget the synthetic addresses within seconds and re-query real
/// DNS servers without a restart.
pub const FAKE_DNS_TTL: u32 = 5;

/// `198.18.0.1` — first usable address in the RFC 2544 range.
pub const FAKE_POOL_FIRST: u32 = 0xC612_0001;
/// `198.19.255.254` — last usable address in the RFC 2544 range.
pub const FAKE_POOL_LAST: u32 = 0xC613_FFFE;
/// Maximum number of live mappings.
pub const FAKE_CACHE_CAPACITY: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum FakeDnsError {
    #[error("malformed DNS message: {0}")]
    Malformed(String),
    #[error("DNS message has no question")]
    NoQuestion,
    #[error("failed to encode DNS response: {0}")]
    Encode(String),
}

/// Result of inspecting one DNS payload.
pub enum DnsDecision {
    /// Synthesised response payload to send back to the client.
    Respond(Vec<u8>),
    /// Not an A query: forward the raw payload as DNS-over-TCP upstream.
    Forward,
}

struct Entry {
    domain: String,
}

struct Inner {
    /// ip -> domain
    by_ip: HashMap<Ipv4Addr, Entry>,
    /// canonical domain -> ip
    by_name: HashMap<String, Ipv4Addr>,
    /// LRU order, oldest at the front. May contain stale duplicates; entries
    /// are validated against `by_name` on eviction.
    order: VecDeque<String>,
    next: u32,
}

impl Inner {
    fn new() -> Self {
        Self {
            by_ip: HashMap::with_capacity(1024),
            by_name: HashMap::with_capacity(1024),
            order: VecDeque::with_capacity(1024),
            next: FAKE_POOL_FIRST,
        }
    }

    fn touch(&mut self, canonical: &str) {
        if let Some(pos) = self.order.iter().position(|d| d == canonical) {
            self.order.remove(pos);
        }
        self.order.push_back(canonical.to_string());
    }

    fn evict_one(&mut self) {
        while let Some(oldest) = self.order.pop_front() {
            if let Some(ip) = self.by_name.remove(&oldest) {
                self.by_ip.remove(&ip);
                return;
            }
        }
    }

    fn allocate(&mut self, canonical: String) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(&canonical) {
            let ip = *ip;
            self.touch(&canonical);
            if let Some(entry) = self.by_ip.get_mut(&ip) {
                entry.domain = canonical;
            }
            return ip;
        }

        while self.by_ip.len() >= FAKE_CACHE_CAPACITY {
            self.evict_one();
        }

        // Find the next free address, defending against a table filled by
        // pre-seeded/restored mappings.
        loop {
            let candidate = Ipv4Addr::from(self.next);
            self.next = if self.next >= FAKE_POOL_LAST {
                FAKE_POOL_FIRST
            } else {
                self.next + 1
            };
            if !self.by_ip.contains_key(&candidate) {
                self.by_ip.insert(
                    candidate,
                    Entry {
                        domain: canonical.clone(),
                    },
                );
                self.by_name.insert(canonical.clone(), candidate);
                self.order.push_back(canonical);
                return candidate;
            }
        }
    }
}

/// Thread-safe Fake-IP allocator and DNS responder.
pub struct FakeDns {
    inner: Mutex<Inner>,
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDns {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Return an existing mapping or allocate a fresh synthetic IPv4 address.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let canonical = canonicalize(domain);
        self.inner.lock().expect("fake dns lock").allocate(canonical)
    }

    /// Map a fake address back to the domain it was allocated for.
    pub fn reverse_lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner
            .lock()
            .expect("fake dns lock")
            .by_ip
            .get(&ip)
            .map(|e| e.domain.clone())
    }

    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
    }

    /// Drop every mapping. Called when a tunnel session ends so stale
    /// 198.18.x.y addresses cannot resolve into a different session.
    pub fn clear(&self) {
        *self.inner.lock().expect("fake dns lock") = Inner::new();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("fake dns lock").by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inspect one raw UDP DNS payload and either synthesise a response or
    /// tell the caller to forward it over TCP.
    pub fn handle_query(&self, payload: &[u8]) -> Result<DnsDecision, FakeDnsError> {
        let query = Message::from_vec(payload)
            .map_err(|e| FakeDnsError::Malformed(e.to_string()))?;
        let question = query
            .queries
            .first()
            .ok_or(FakeDnsError::NoQuestion)?;
        let name = question.name().clone();
        let qtype = question.query_type();

        match qtype {
            RecordType::A => {
                let domain = name.to_utf8();
                let ip = self.allocate(&domain);
                let response = build_response(&query, &name, Some(ip))
                    .map_err(FakeDnsError::Encode)?;
                Ok(DnsDecision::Respond(response))
            }
            // Force clients onto IPv4 fake IPs. Returning NODATA (rather than
            // NXDOMAIN) keeps happy-eyeballs and HTTPS-record users working.
            RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB => {
                let response =
                    build_response(&query, &name, None).map_err(FakeDnsError::Encode)?;
                Ok(DnsDecision::Respond(response))
            }
            _ => Ok(DnsDecision::Forward),
        }
    }
}

/// Build a response echoing the query name and ID.
pub(crate) fn build_response(
    query: &Message,
    name: &Name,
    answer: Option<Ipv4Addr>,
) -> Result<Vec<u8>, String> {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = false;
    response.queries = query.queries.clone();
    if let Some(ip) = answer {
        let record = Record::from_rdata(name.clone(), FAKE_DNS_TTL, RData::A(A(ip)));
        response.add_answer(record);
    }
    response.to_vec().map_err(|e| e.to_string())
}

fn canonicalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};

    fn a_query(domain: &str) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_utf8(domain).unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_vec().unwrap()
    }

    fn query_of(domain: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        let name = Name::from_utf8(domain).unwrap();
        msg.add_query(Query::query(name, qtype));
        msg.to_vec().unwrap()
    }

    #[test]
    fn allocates_deterministic_sequential_addresses() {
        let dns = FakeDns::new();
        let a = dns.allocate("example.com");
        let b = dns.allocate("example.org");
        let a2 = dns.allocate("EXAMPLE.COM.");
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(b, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(a, a2, "canonical names must map to the same IP");
        assert_eq!(dns.reverse_lookup(a).as_deref(), Some("example.com"));
        assert_eq!(dns.len(), 2);
    }

    #[test]
    fn answers_a_with_ttl_5_and_reverse_lookup() {
        let dns = FakeDns::new();
        let payload = a_query("verify.proxybase.xyz");
        let DnsDecision::Respond(bytes) = dns.handle_query(&payload).unwrap() else {
            panic!("A query must be answered locally");
        };
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 1);
        let answer = &msg.answers[0];
        assert_eq!(answer.ttl, FAKE_DNS_TTL);
        let ip = match &answer.data {
            RData::A(a) => a.0,
            other => panic!("unexpected rdata {other:?}"),
        };
        assert!(dns.is_fake_ip(ip));
        assert_eq!(
            dns.reverse_lookup(ip).as_deref(),
            Some("verify.proxybase.xyz")
        );
    }

    #[test]
    fn aaaa_and_https_return_nodata() {
        let dns = FakeDns::new();
        for qtype in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let payload = query_of("cloudflare.com", qtype);
            let DnsDecision::Respond(bytes) = dns.handle_query(&payload).unwrap() else {
                panic!("{qtype} must be answered with NODATA");
            };
            let msg = Message::from_vec(&bytes).unwrap();
            assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
            assert!(msg.answers.is_empty());
        }
        assert_eq!(dns.len(), 0, "no fake IP for AAAA/HTTPS");
    }

    #[test]
    fn forwards_other_query_types() {
        let dns = FakeDns::new();
        let payload = query_of("example.com", RecordType::MX);
        assert!(matches!(
            dns.handle_query(&payload).unwrap(),
            DnsDecision::Forward
        ));
    }

    #[test]
    fn test_fake_dns_allocation_and_lru_eviction() {
        let dns = FakeDns::new();
        for i in 0..1_000 {
            let domain = format!("host-{i}.example.com");
            let payload = a_query(&domain);
            let DnsDecision::Respond(bytes) = dns.handle_query(&payload).unwrap() else {
                panic!("A query must be answered locally");
            };
            let msg = Message::from_vec(&bytes).unwrap();
            let answer = &msg.answers[0];
            assert_eq!(answer.ttl, FAKE_DNS_TTL);
            let ip = match &answer.data {
                RData::A(a) => a.0,
                other => panic!("unexpected rdata {other:?}"),
            };
            let octets = ip.octets();
            assert_eq!(octets[0], 198);
            assert!(octets[1] == 18 || octets[1] == 19);
            assert_eq!(dns.reverse_lookup(ip).as_deref(), Some(domain.as_str()));
        }

        // AAAA and HTTPS (type 65) must be NODATA, never synthetic A records.
        for qtype in [RecordType::AAAA, RecordType::HTTPS] {
            let payload = query_of("cloudflare.com", qtype);
            let DnsDecision::Respond(bytes) = dns.handle_query(&payload).unwrap() else {
                panic!("{qtype} must be answered locally");
            };
            let msg = Message::from_vec(&bytes).unwrap();
            assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
            assert!(msg.answers.is_empty());
        }
    }

    #[test]
    fn lru_eviction_bounds_cache() {
        let dns = FakeDns::new();
        let keep = dns.allocate("keep.example.com");
        for i in 0..FAKE_CACHE_CAPACITY - 1 {
            dns.allocate(&format!("host-{i}.example.com"));
        }
        assert_eq!(dns.len(), FAKE_CACHE_CAPACITY);
        // Touch `keep`, then insert one more: the oldest untouched entry is
        // evicted, not the recently used one.
        assert_eq!(dns.allocate("KEEP.example.com."), keep);
        dns.allocate("new.example.com");
        assert_eq!(dns.len(), FAKE_CACHE_CAPACITY);
        assert!(dns.reverse_lookup(keep).is_some());
    }
}
