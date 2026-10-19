//! Raw IPv4/IPv6 packet inspection and synthesis.
//!
//! This module deliberately parses packets by hand instead of trusting a
//! high-level stack. The tunnel must be able to:
//!
//! * clamp the TCP MSS in SYN / SYN-ACK packets before they reach the kernel
//!   or the userspace stack,
//! * answer UDP:53 locally with a fake IP,
//! * synthesise ICMP port-unreachable for QUIC (UDP:443),
//! * drop STUN datagrams, and
//! * quote the original packet in ICMP errors exactly as RFC 792 / RFC 4443
//!   require.
//!
//! Every function that mutates a packet recomputes the affected checksum.

use crate::tunnel::fake_dns::{DnsDecision, FakeDns, FakeDnsError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMPV6: u8 = 58;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// Parsed transport metadata for one IP packet.
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// Offset of the L4 header (TCP/UDP/ICMP) inside the packet.
    pub l4_offset: usize,
    /// End offset of the L4 payload (usually the IP total length).
    pub end: usize,
}

impl PacketInfo {
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        let start = self.l4_offset + transport_header_len(self.protocol, &packet[self.l4_offset..self.end]);
        if start <= self.end {
            &packet[start..self.end]
        } else {
            &[]
        }
    }

    pub fn is_tcp(&self) -> bool {
        self.protocol == IPPROTO_TCP
    }

    pub fn is_udp(&self) -> bool {
        self.protocol == IPPROTO_UDP
    }

    pub fn tcp_flags(&self, packet: &[u8]) -> Option<u8> {
        if !self.is_tcp() || self.l4_offset + 14 > self.end || self.end > packet.len() {
            return None;
        }
        Some(packet[self.l4_offset + 13])
    }
}

/// Result of inspecting one packet travelling from the OS into the TUN device.
#[derive(Debug)]
pub enum PacketDecision {
    /// Deliver (possibly rewritten) packet to the userspace TCP/IP stack.
    Forward(Vec<u8>),
    /// Silently drop (STUN, malformed DNS, ...).
    Drop,
    /// Write this synthetic packet back into the TUN device.
    Reply(Vec<u8>),
    /// Non-A DNS query: resolve over DNS-over-TCP through the proxy.
    ForwardDns {
        query: Vec<u8>,
        /// Original packet, retained to address the UDP response.
        original: Vec<u8>,
    },
}

/// Parsed packet cannot be handled safely; the caller should pass it through
/// unchanged (or drop it) rather than misinterpret lengths.
pub fn parse(packet: &[u8]) -> Option<PacketInfo> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    let fragment_offset = frag & 0x1fff;
    let more_fragments = frag & 0x2000 != 0;
    // A non-initial fragment has no L4 header; let the stack deal with it.
    if fragment_offset != 0 {
        return Some(PacketInfo {
            version: 4,
            src: IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
            dst: IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
            protocol: packet[9],
            src_port: 0,
            dst_port: 0,
            l4_offset: total_len,
            end: total_len,
        });
    }
    let _ = more_fragments;
    let protocol = packet[9];
    let (src_port, dst_port) = ports_at(packet, protocol, ihl, total_len)?;
    Some(PacketInfo {
        version: 4,
        src: IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
        dst: IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
        protocol,
        src_port,
        dst_port,
        l4_offset: ihl,
        end: total_len,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = 40 + payload_len;
    if end > packet.len() {
        return None;
    }
    let mut next = packet[6];
    let mut offset = 40;
    // Walk the extension-header chain. Each header carries the next-header
    // value and its own length (except the fragment header, which is fixed).
    let mut guard = 0;
    while matches!(next, 0 | 43 | 44 | 51 | 60) {
        guard += 1;
        if guard > 8 || offset + 2 > end {
            return None;
        }
        let hdr_len = match next {
            44 => 8,                       // Fragment
            51 => (packet[offset + 1] as usize + 2) * 4, // AH
            _ => (packet[offset + 1] as usize + 1) * 8,  // Hop-by-hop / routing / dest
        };
        if hdr_len < 8 || offset + hdr_len > end {
            return None;
        }
        next = packet[offset];
        offset += hdr_len;
    }
    let (src_port, dst_port) = ports_at(packet, next, offset, end)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    Some(PacketInfo {
        version: 6,
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol: next,
        src_port,
        dst_port,
        l4_offset: offset,
        end,
    })
}

fn ports_at(packet: &[u8], protocol: u8, offset: usize, end: usize) -> Option<(u16, u16)> {
    match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            if offset + 4 > end {
                return None;
            }
            Some((
                u16::from_be_bytes([packet[offset], packet[offset + 1]]),
                u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
            ))
        }
        _ => Some((0, 0)),
    }
}

fn transport_header_len(protocol: u8, l4: &[u8]) -> usize {
    match protocol {
        IPPROTO_TCP => {
            if l4.len() >= 13 {
                ((l4[12] >> 4) as usize * 4).max(20)
            } else {
                20
            }
        }
        IPPROTO_UDP => 8,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

/// Packet filter driven by the tunnel configuration.
pub struct PacketFilter {
    pub disable_quic_udp_443: bool,
    pub block_webrtc_stun: bool,
    pub clamp_mss: u16,
    pub fake_dns: Arc<FakeDns>,
}

impl PacketFilter {
    pub fn new(
        disable_quic_udp_443: bool,
        block_webrtc_stun: bool,
        clamp_mss: u16,
        fake_dns: Arc<FakeDns>,
    ) -> Self {
        Self {
            disable_quic_udp_443,
            block_webrtc_stun,
            clamp_mss,
            fake_dns,
        }
    }

    /// Inspect a packet read from the TUN device (OS -> network).
    pub fn inspect_outbound(&self, packet: &[u8]) -> PacketDecision {
        let Some(info) = parse(packet) else {
            return PacketDecision::Forward(packet.to_vec());
        };

        if info.is_tcp() {
            // Clamp the MSS advertised by the OS in SYN and SYN-ACK so the
            // remote side never sends segments larger than the tunnel path.
            let is_syn = info
                .tcp_flags(packet)
                .map(|f| f & TCP_FLAG_SYN != 0)
                .unwrap_or(false);
            let _ = TCP_FLAG_ACK;
            if is_syn {
                let mut out = packet.to_vec();
                clamp_tcp_mss(&mut out, self.clamp_mss);
                return PacketDecision::Forward(out);
            }
            return PacketDecision::Forward(packet.to_vec());
        }

        if info.is_udp() {
            if info.l4_offset + 8 > info.end || info.end > packet.len() {
                return PacketDecision::Forward(packet.to_vec());
            }
            let payload = &packet[info.l4_offset + 8..info.end];

            if info.dst_port == 53 {
                match self.fake_dns.handle_query(payload) {
                    Ok(DnsDecision::Respond(resp)) => {
                        if let Some(reply) = build_udp_response(packet, &info, &resp) {
                            return PacketDecision::Reply(reply);
                        }
                        return PacketDecision::Drop;
                    }
                    Ok(DnsDecision::Forward) => {
                        return PacketDecision::ForwardDns {
                            query: payload.to_vec(),
                            original: packet.to_vec(),
                        };
                    }
                    Err(FakeDnsError::Malformed(_)) | Err(FakeDnsError::NoQuestion) => {
                        return PacketDecision::Drop;
                    }
                    Err(FakeDnsError::Encode(_)) => return PacketDecision::Drop,
                }
            }

            if self.disable_quic_udp_443 && info.dst_port == 443 {
                return match build_icmp_port_unreachable(packet, &info) {
                    Some(reply) => PacketDecision::Reply(reply),
                    None => PacketDecision::Drop,
                };
            }

            if self.block_webrtc_stun && is_stun_datagram(payload, info.dst_port) {
                return PacketDecision::Drop;
            }

            return PacketDecision::Forward(packet.to_vec());
        }

        PacketDecision::Forward(packet.to_vec())
    }

    /// Packets produced by the userspace stack on their way to the OS.
    /// SYN-ACKs get the same MSS clamp as outbound SYNs.
    pub fn inspect_inbound(&self, packet: &[u8]) -> Vec<u8> {
        let Some(info) = parse(packet) else {
            return packet.to_vec();
        };
        let is_syn = info
            .tcp_flags(packet)
            .map(|f| f & TCP_FLAG_SYN != 0)
            .unwrap_or(false);
        if info.is_tcp() && is_syn {
            let mut out = packet.to_vec();
            clamp_tcp_mss(&mut out, self.clamp_mss);
            return out;
        }
        packet.to_vec()
    }
}

/// RFC 5389 STUN magic cookie and the UDP ports commonly used by WebRTC.
pub fn is_stun_datagram(payload: &[u8], dst_port: u16) -> bool {
    const STUN_PORTS: [u16; 3] = [3478, 5349, 19302];
    if STUN_PORTS.contains(&dst_port) && payload.len() >= 20 {
        return true;
    }
    if payload.len() >= 8 {
        // Top two bits of the STUN message type are zero; magic cookie at
        // bytes 4..8.
        let zero_prefix = payload[0] & 0xC0 == 0;
        return zero_prefix && payload[4..8] == [0x21, 0x12, 0xA4, 0x42];
    }
    false
}

// ---------------------------------------------------------------------------
// MSS clamping
// ---------------------------------------------------------------------------

/// Clamp the TCP MSS option in `packet` to `mss` and recompute the TCP
/// checksum. Returns `true` when the packet was modified.
///
/// Packets without an MSS option (including non-SYN packets) are untouched.
pub fn clamp_tcp_mss(packet: &mut [u8], mss: u16) -> bool {
    let Some(info) = parse(packet) else {
        return false;
    };
    if !info.is_tcp() {
        return false;
    }
    let tcp = info.l4_offset;
    if tcp + 20 > info.end {
        return false;
    }
    let data_offset = ((packet[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp + data_offset > info.end {
        return false;
    }
    let options_end = tcp + data_offset;
    let mut i = tcp + 20;
    let mut changed = false;
    while i < options_end {
        let kind = packet[i];
        if kind == 0 {
            break; // End of option list
        }
        if kind == 1 {
            i += 1;
            continue; // NOP
        }
        if i + 1 >= options_end {
            break;
        }
        let len = packet[i + 1] as usize;
        if len < 2 || i + len > options_end {
            break;
        }
        if kind == 2 && len == 4 {
            packet[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
            changed = true;
        }
        i += len;
    }
    if changed {
        let checksum_offset = tcp + 16;
        packet[checksum_offset] = 0;
        packet[checksum_offset + 1] = 0;
        let csum = transport_checksum(packet, &info);
        packet[checksum_offset..checksum_offset + 2].copy_from_slice(&csum.to_be_bytes());
    }
    changed
}

/// Read the MSS option from a TCP packet, if present (test/diagnostics helper).
pub fn tcp_mss(packet: &[u8]) -> Option<u16> {
    let info = parse(packet)?;
    if !info.is_tcp() {
        return None;
    }
    let tcp = info.l4_offset;
    if tcp + 20 > info.end {
        return None;
    }
    let data_offset = ((packet[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp + data_offset > info.end {
        return None;
    }
    let mut i = tcp + 20;
    while i < tcp + data_offset {
        let kind = packet[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= tcp + data_offset {
            break;
        }
        let len = packet[i + 1] as usize;
        if len < 2 || i + len > tcp + data_offset {
            break;
        }
        if kind == 2 && len == 4 {
            return Some(u16::from_be_bytes([packet[i + 2], packet[i + 3]]));
        }
        i += len;
    }
    None
}

// ---------------------------------------------------------------------------
// Synthetic responses
// ---------------------------------------------------------------------------

/// Build a UDP datagram carrying `payload`, addressed back to the sender of
/// `original`.
pub fn build_udp_response(original: &[u8], info: &PacketInfo, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > u16::MAX as usize - 8 {
        return None;
    }
    let udp_len = 8 + payload.len();
    match (info.src, info.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20 + udp_len;
            if total > 65_535 {
                return None;
            }
            let mut out = vec![0u8; total];
            out[0] = 0x45;
            out[1] = original[1] & 0xfc; // preserve DSCP/ECN
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[4..6].copy_from_slice(&[0, 0]); // no fragmentation
            out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            out[8] = 64;
            out[9] = IPPROTO_UDP;
            out[12..16].copy_from_slice(&dst.octets()); // reply from original destination
            out[16..20].copy_from_slice(&src.octets());
            let ip_csum = checksum(&out[..20]);
            out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            let udp = 20;
            out[udp..udp + 2].copy_from_slice(&info.dst_port.to_be_bytes());
            out[udp + 2..udp + 4].copy_from_slice(&info.src_port.to_be_bytes());
            out[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[udp + 8..].copy_from_slice(payload);
            let sum = pseudo_header_v4(dst, src, IPPROTO_UDP, udp_len)
                + sum_words(&out[udp..]);
            let csum = finish_checksum(sum);
            // A zero UDP checksum means "no checksum" in IPv4. RFC 768 allows
            // it, but sending the computed value is more useful to middleboxes.
            out[udp + 6..udp + 8].copy_from_slice(&if csum == 0 { 0xffff } else { csum }.to_be_bytes());
            Some(out)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let total = 40 + udp_len;
            if total > 65_535 + 40 {
                return None;
            }
            let mut out = vec![0u8; total];
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[6] = IPPROTO_UDP;
            out[7] = 64;
            out[8..24].copy_from_slice(&dst.octets());
            out[24..40].copy_from_slice(&src.octets());
            let udp = 40;
            out[udp..udp + 2].copy_from_slice(&info.dst_port.to_be_bytes());
            out[udp + 2..udp + 4].copy_from_slice(&info.src_port.to_be_bytes());
            out[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[udp + 8..].copy_from_slice(payload);
            let sum = pseudo_header_v6(dst, src, IPPROTO_UDP, udp_len)
                + sum_words(&out[udp..]);
            let csum = finish_checksum(sum);
            out[udp + 6..udp + 8].copy_from_slice(&if csum == 0 { 0xffff } else { csum }.to_be_bytes());
            Some(out)
        }
        _ => None,
    }
}

/// ICMP Destination Unreachable / Port Unreachable for the quoted packet.
pub fn build_icmp_port_unreachable(original: &[u8], info: &PacketInfo) -> Option<Vec<u8>> {
    match info.version {
        4 => {
            let quote_len = quote_len_v4(original);
            let icmp_len = 8 + quote_len;
            let total = 20 + icmp_len;
            if total > 65_535 {
                return None;
            }
            let mut out = vec![0u8; total];
            out[0] = 0x45;
            out[1] = original[1] & 0xfc;
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            out[8] = 64;
            out[9] = IPPROTO_ICMP;
            if let (IpAddr::V4(src), IpAddr::V4(dst)) = (info.src, info.dst) {
                out[12..16].copy_from_slice(&dst.octets());
                out[16..20].copy_from_slice(&src.octets());
            } else {
                return None;
            }
            let csum = checksum(&out[..20]);
            out[10..12].copy_from_slice(&csum.to_be_bytes());
            let icmp = 20;
            out[icmp] = 3; // Destination Unreachable
            out[icmp + 1] = 3; // Port Unreachable
            out[icmp + 8..icmp + 8 + quote_len].copy_from_slice(&original[..quote_len]);
            let csum = checksum(&out[icmp..]);
            out[icmp + 2..icmp + 4].copy_from_slice(&csum.to_be_bytes());
            Some(out)
        }
        6 => build_icmpv6_unreachable(original, info, 4),
        _ => None,
    }
}

/// ICMPv6 Destination Unreachable (type 1) with the requested code.
/// Code 0 = no route to destination, 4 = port unreachable.
pub fn build_icmpv6_unreachable(
    original: &[u8],
    info: &PacketInfo,
    code: u8,
) -> Option<Vec<u8>> {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (info.src, info.dst) else {
        return None;
    };
    // ICMPv6 error messages should be at most 1280 bytes end-to-end.
    let max_icmp_payload = 1280usize.saturating_sub(40 + 8);
    let quote_len = original.len().min(max_icmp_payload).min(original.len());
    let icmp_len = 8 + quote_len;
    let total = 40 + icmp_len;
    let mut out = vec![0u8; total];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    out[6] = IPPROTO_ICMPV6;
    out[7] = 64;
    out[8..24].copy_from_slice(&dst.octets());
    out[24..40].copy_from_slice(&src.octets());
    let icmp = 40;
    out[icmp] = 1; // Destination Unreachable
    out[icmp + 1] = code;
    out[icmp + 8..icmp + 8 + quote_len].copy_from_slice(&original[..quote_len]);
    let sum = pseudo_header_v6(dst, src, IPPROTO_ICMPV6, icmp_len) + sum_words(&out[icmp..]);
    let csum = finish_checksum(sum);
    out[icmp + 2..icmp + 4].copy_from_slice(&csum.to_be_bytes());
    Some(out)
}

fn quote_len_v4(packet: &[u8]) -> usize {
    let Some(info) = parse(packet) else {
        return packet.len().min(28);
    };
    // RFC 792: Internet header + 64 bits of original data.
    (info.l4_offset + 8).min(packet.len())
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

fn pseudo_header_v4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, len: usize) -> u32 {
    sum_words(&src.octets())
        + sum_words(&dst.octets())
        + (protocol as u32)
        + (len as u32)
}

fn pseudo_header_v6(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, len: usize) -> u32 {
    sum_words(&src.octets())
        + sum_words(&dst.octets())
        + ((len >> 16) as u32)
        + ((len & 0xffff) as u32)
        + (protocol as u32)
}

fn transport_checksum(packet: &[u8], info: &PacketInfo) -> u16 {
    let seg = &packet[info.l4_offset..info.end];
    let mut sum = match (info.src, info.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            pseudo_header_v4(src, dst, info.protocol, seg.len())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            pseudo_header_v6(src, dst, info.protocol, seg.len())
        }
        _ => 0,
    };
    sum += sum_words(seg);
    finish_checksum(sum)
}

/// One's-complement sum of 16-bit big-endian words.
pub fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for word in &mut chunks {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    sum
}

pub fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    finish_checksum(sum_words(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{Ipv4Header, TcpHeader, UdpHeader};

    fn ipv4_tcp_syn(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, mss: u16) -> Vec<u8> {
        let mut tcp = TcpHeader::new(src_port, dst_port, 1000, 64240);
        tcp.syn = true;
        tcp.ack = false;
        tcp.options = etherparse::TcpOptions::try_from(
            &[etherparse::TcpOptionElement::MaximumSegmentSize(mss)][..],
        )
        .unwrap();
        let payload: &[u8] = &[];
        let mut ip = Ipv4Header::new(
            tcp.header_len() as u16 + payload.len() as u16,
            64,
            etherparse::IpNumber::TCP,
            src,
            dst,
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut out = Vec::new();
        ip.write(&mut out).unwrap();
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    fn ipv4_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = UdpHeader {
            source_port: src_port,
            destination_port: dst_port,
            length: (8 + payload.len()) as u16,
            checksum: 0,
        };
        let mut ip = Ipv4Header::new(
            udp.length,
            64,
            etherparse::IpNumber::UDP,
            src,
            dst,
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut out = Vec::new();
        ip.write(&mut out).unwrap();
        udp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        // etherparse's UdpHeader::write doesn't compute the checksum; tests
        // below don't need it for parsing.
        out
    }

    #[test]
    fn test_tcp_mss_clamping_checksum_validity() {
        let mut pkt = ipv4_tcp_syn([10, 255, 0, 2], [1, 1, 1, 1], 54321, 443, 1460);
        assert_eq!(tcp_mss(&pkt), Some(1460));
        assert!(clamp_tcp_mss(&mut pkt, 1340));
        assert_eq!(tcp_mss(&pkt), Some(1340));
        // Full parse validates checksums (Ipv4HeaderSlice/TcpHeaderSlice).
        let ip = etherparse::Ipv4HeaderSlice::from_slice(&pkt).unwrap();
        assert_eq!(
            ip.header_checksum(),
            ip.to_header().calc_header_checksum()
        );
        let payload = &pkt[ip.slice().len()..];
        let tcp = etherparse::TcpHeaderSlice::from_slice(payload).unwrap();
        let tcp_bytes = &payload[..tcp.slice().len()];
        let expected = tcp
            .to_header()
            .calc_checksum_ipv4(&ip.to_header(), &payload[tcp_bytes.len()..])
            .unwrap();
        assert_eq!(tcp.checksum(), expected);
    }

    #[test]
    fn leaves_packets_without_mss_untouched() {
        // No options at all: header data offset 5 (20 bytes).
        let mut tcp = TcpHeader::new(1234, 443, 1000, 64240);
        tcp.syn = true;
        let ip = Ipv4Header::new(
            tcp.header_len() as u16,
            64,
            etherparse::IpNumber::TCP,
            [10, 255, 0, 2],
            [1, 1, 1, 1],
        )
        .unwrap();
        let mut pkt = Vec::new();
        ip.write(&mut pkt).unwrap();
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &[]).unwrap();
        tcp.write(&mut pkt).unwrap();
        let before = pkt.clone();
        assert!(!clamp_tcp_mss(&mut pkt, 1340));
        assert_eq!(pkt, before);
    }

    #[test]
    fn builds_valid_icmp_port_unreachable() {
        let pkt = ipv4_udp([10, 255, 0, 2], [142, 250, 190, 46], 54321, 443, b"hello");
        let info = parse(&pkt).unwrap();
        let icmp = build_icmp_port_unreachable(&pkt, &info).unwrap();
        let ip = etherparse::Ipv4HeaderSlice::from_slice(&icmp).unwrap();
        assert_eq!(ip.protocol(), etherparse::IpNumber::ICMP);
        assert_eq!(ip.source_addr(), Ipv4Addr::new(142, 250, 190, 46));
        assert_eq!(ip.destination_addr(), Ipv4Addr::new(10, 255, 0, 2));
        let icmp_bytes = &icmp[ip.slice().len()..];
        assert_eq!(icmp_bytes[0], 3);
        assert_eq!(icmp_bytes[1], 3);
        assert_eq!(checksum(icmp_bytes), 0, "ICMP checksum must verify to zero");
        assert_eq!(&icmp_bytes[8..8 + 28], &pkt[..28]);
    }

    #[test]
    fn builds_valid_udp_dns_reply() {
        let query = ipv4_udp([10, 255, 0, 2], [8, 8, 8, 8], 40000, 53, b"\x12\x34dns");
        let info = parse(&query).unwrap();
        let reply = build_udp_response(&query, &info, b"answer").unwrap();
        let ip = etherparse::Ipv4HeaderSlice::from_slice(&reply).unwrap();
        assert_eq!(ip.source_addr(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip.destination_addr(), Ipv4Addr::new(10, 255, 0, 2));
        let udp = etherparse::UdpHeaderSlice::from_slice(&reply[ip.slice().len()..]).unwrap();
        assert_eq!(udp.source_port(), 53);
        assert_eq!(udp.destination_port(), 40000);
        assert_ne!(udp.checksum(), 0);
    }

    #[test]
    fn detects_stun_magic_cookie() {
        let mut payload = vec![0u8; 20];
        payload[0] = 0x00;
        payload[1] = 0x01;
        payload[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert!(is_stun_datagram(&payload, 50000));
        assert!(is_stun_datagram(&[0u8; 20], 19302));
        assert!(!is_stun_datagram(b"not stun", 50000));
    }

    #[test]
    fn test_quic_udp_443_icmp_rejection() {
        let dns = Arc::new(FakeDns::new());
        let filter = PacketFilter::new(true, true, 1340, dns);
        let pkt = ipv4_udp([10, 255, 0, 2], [142, 250, 190, 46], 54321, 443, b"quic");
        match filter.inspect_outbound(&pkt) {
            PacketDecision::Reply(reply) => {
                let ip = etherparse::Ipv4HeaderSlice::from_slice(&reply).unwrap();
                assert_eq!(ip.protocol(), etherparse::IpNumber::ICMP);
                let icmp = &reply[ip.slice().len()..];
                assert_eq!((icmp[0], icmp[1]), (3, 3));
            }
            other => panic!("expected ICMP reply, got {other:?}"),
        }
    }

    #[test]
    fn test_webrtc_stun_magic_cookie_blocker() {
        let filter = PacketFilter::new(true, true, 1340, Arc::new(FakeDns::new()));
        let mut payload = vec![0u8; 20];
        payload[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let pkt = ipv4_udp([10, 255, 0, 2], [1, 2, 3, 4], 50000, 19302, &payload);
        assert!(matches!(
            filter.inspect_outbound(&pkt),
            PacketDecision::Drop
        ));
    }
}
