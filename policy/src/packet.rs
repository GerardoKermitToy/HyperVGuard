use hyperv_protocol::{Connection, Direction, MAX_PAYLOAD, connection_header_len};

pub const SNAPSHOT: usize = 320;

// Raw C-shim values describe ownership on the host vNIC, not wire direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NdisPath {
    Send = 0,
    Receive = 1,
}
impl NdisPath {
    pub const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Send),
            1 => Some(Self::Receive),
            _ => None,
        }
    }
    pub const fn direction(self) -> Direction {
        // Host receive comes from the guest; host send goes towards the guest.
        match self {
            Self::Send => Direction::Inbound,
            Self::Receive => Direction::Outbound,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub l2: [u8; 22],
    pub l2_len: u8,
    pub ipv6: bool,
    pub protocol: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
}
impl Flow {
    pub const EMPTY: Self = Self {
        l2: [0; 22],
        l2_len: 0,
        ipv6: false,
        protocol: 0,
        source: [0; 16],
        destination: [0; 16],
        source_port: 0,
        destination_port: 0,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub flow: Flow,
    pub connection: Connection,
    pub cacheable: bool,
    pub ip_len: u64,      // Total bytes for bandwidth; can aggregate same-flow NBs.
    pub payload_len: u32, // Complete IP packet in the first NB, without Ethernet padding.
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureLayout {
    pub record_len: usize,
    pub frame_start: usize,
    pub frame_len: usize,
}
impl Packet {
    pub const EMPTY: Self = Self {
        flow: Flow::EMPTY,
        connection: Connection::EMPTY,
        cacheable: false,
        ip_len: 0,
        payload_len: 0,
    };
    // Leave room for the wire prefix and copy Ethernet+IP straight into the final
    // allocation. Encoding the prefix later overwrites only the Ethernet bytes.
    pub fn capture_layout(&self) -> Option<CaptureLayout> {
        let payload_len = self.payload_len as usize;
        if payload_len > MAX_PAYLOAD {
            return None;
        }
        let prefix = connection_header_len(&self.connection);
        let l2_len = usize::from(self.flow.l2_len);
        Some(CaptureLayout {
            record_len: prefix + payload_len,
            frame_start: prefix.checked_sub(l2_len)?,
            frame_len: l2_len + payload_len,
        })
    }
    // One verdict covers a homogeneous NBL; only the first NB supplies payload.
    // The chain has no count quota and can account for more than u32::MAX bytes.
    pub fn merge(&mut self, other: &Self) -> Result<(), ParseError> {
        if self.flow != other.flow {
            return Err(ParseError::Malformed);
        }
        self.ip_len = self.ip_len.saturating_add(other.ip_len);
        self.cacheable = false;
        Ok(())
    }
    pub fn orient(&mut self, path: NdisPath) {
        let direction = path.direction();
        self.connection.direction = direction;
        let (local_ip, remote_ip, local_port, remote_port) = match direction {
            Direction::Outbound => (
                self.flow.source,
                self.flow.destination,
                self.flow.source_port,
                self.flow.destination_port,
            ),
            Direction::Inbound => (
                self.flow.destination,
                self.flow.source,
                self.flow.destination_port,
                self.flow.source_port,
            ),
        };
        self.connection.local_ip = local_ip;
        self.connection.remote_ip = remote_ip;
        self.connection.local_port = local_port;
        self.connection.remote_port = remote_port;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    Malformed,
    TooManyVlans,
    TooLarge,
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

// Only read policy fields from the copied NDIS host-memory prefix. Both headers
// and payload remain untrusted network input and all offsets are checked.
// None means a non-IP Ethernet control frame, outside the legacy L3 wire API.
pub fn parse(
    data: &[u8],
    trusted_len: usize,
    frame_len: usize,
    offload: bool,
) -> Result<Option<Packet>, ParseError> {
    let trusted = &data[..trusted_len.min(data.len())];
    if trusted.len() < 14 || frame_len < 14 {
        return Err(ParseError::Truncated);
    }
    let mut offset = 14;
    let mut ether_type = be16(trusted, 12);
    let mut tags = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if tags == 2 {
            return Err(ParseError::TooManyVlans);
        }
        if trusted.len() < offset + 4 || frame_len < offset + 4 {
            return Err(ParseError::Truncated);
        }
        ether_type = be16(trusted, offset + 2);
        offset += 4;
        tags += 1;
    }
    if !matches!(ether_type, 0x0800 | 0x86dd) {
        return Ok(None);
    }
    let ip = &trusted[offset..];
    let logical = frame_len.checked_sub(offset).ok_or(ParseError::Truncated)?;
    let mut p = Packet::EMPTY;
    p.flow.l2[..offset].copy_from_slice(&trusted[..offset]);
    p.flow.l2_len = offset as u8;
    let (mut transport, mut proto, fragmented, ip_len) = if ether_type == 0x0800 {
        if ip.len() < 20 {
            return Err(ParseError::Truncated);
        }
        let ihl = usize::from(ip[0] & 15) * 4;
        let total = usize::from(be16(ip, 2));
        if ip[0] >> 4 != 4 || ihl < 20 || total < ihl && !offload {
            return Err(ParseError::Malformed);
        }
        if ip.len() < ihl || logical < ihl {
            return Err(ParseError::Truncated);
        }
        if total > logical && !offload {
            return Err(ParseError::Truncated);
        }
        p.flow.source[..4].copy_from_slice(&ip[12..16]);
        p.flow.destination[..4].copy_from_slice(&ip[16..20]);
        (
            ihl,
            ip[9],
            be16(ip, 6) & 0x3fff != 0,
            if offload { logical } else { total },
        )
    } else {
        if ip.len() < 40 || logical < 40 {
            return Err(ParseError::Truncated);
        }
        if ip[0] >> 4 != 6 {
            return Err(ParseError::Malformed);
        }
        let payload = usize::from(be16(ip, 4));
        let total = if payload == 0 || offload {
            logical
        } else {
            40 + payload
        };
        if total > logical {
            return Err(ParseError::Truncated);
        }
        p.flow.ipv6 = true;
        p.flow.source.copy_from_slice(&ip[8..24]);
        p.flow.destination.copy_from_slice(&ip[24..40]);
        (40, ip[6], false, total)
    };
    if ip_len > MAX_PAYLOAD {
        return Err(ParseError::TooLarge);
    }
    let mut fragment = fragmented;
    let mut fully_parsed = true;
    if p.flow.ipv6 {
        let mut steps = 0;
        while matches!(proto, 0 | 43 | 60 | 44 | 51) {
            steps += 1;
            if steps > 8 || transport + 2 > ip.len() {
                fully_parsed = false;
                break;
            }
            let len = match proto {
                44 => 8,
                51 => (usize::from(ip[transport + 1]) + 2) * 4,
                _ => (usize::from(ip[transport + 1]) + 1) * 8,
            };
            if transport + len > ip_len {
                return Err(ParseError::Malformed);
            }
            if transport + len > ip.len() {
                fully_parsed = false;
                break;
            }
            let next = ip[transport];
            let non_initial = proto == 44 && be16(ip, transport + 2) & 0xfff8 != 0;
            fragment |= proto == 44;
            transport += len;
            proto = next;
            if non_initial {
                fully_parsed = false;
                break;
            }
        }
    }
    if fully_parsed && !fragment && matches!(proto, 6 | 17) {
        let min = if proto == 6 { 20 } else { 8 };
        if transport + min > ip_len {
            return Err(ParseError::Malformed);
        }
        if transport + min <= ip.len() {
            if proto == 6 {
                let tcp_len = usize::from(ip[transport + 12] >> 4) * 4;
                if tcp_len < 20 || transport + tcp_len > ip_len {
                    return Err(ParseError::Malformed);
                }
            } else if be16(ip, transport + 4) < 8 && !offload {
                return Err(ParseError::Malformed);
            }
            p.flow.source_port = be16(ip, transport);
            p.flow.destination_port = be16(ip, transport + 2);
            p.cacheable = !offload;
        }
    }
    p.flow.protocol = proto;
    p.ip_len = ip_len as u64;
    p.connection.ipv6 = p.flow.ipv6;
    p.connection.protocol = proto;
    p.connection.local_ip = p.flow.source;
    p.connection.remote_ip = p.flow.destination;
    p.connection.local_port = p.flow.source_port;
    p.connection.remote_port = p.flow.destination_port;
    p.payload_len = ip_len as u32;
    Ok(Some(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn udp() -> [u8; 64] {
        let mut b = [0; 64];
        b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        b[14] = 0x45;
        b[16..18].copy_from_slice(&28u16.to_be_bytes());
        b[23] = 17;
        b[26..30].copy_from_slice(&[10, 0, 0, 1]);
        b[30..34].copy_from_slice(&[10, 0, 0, 2]);
        b[34..36].copy_from_slice(&1234u16.to_be_bytes());
        b[36..38].copy_from_slice(&53u16.to_be_bytes());
        b[38..40].copy_from_slice(&8u16.to_be_bytes());
        b
    }
    #[test]
    fn ipv4_udp_network_payload_and_ports() {
        let b = udp();
        let p = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        assert!(p.cacheable);
        assert_eq!(p.flow.source_port, 1234);
        assert_eq!(p.payload_len, 28);
        assert_eq!(p.ip_len, 28);
    }
    #[test]
    fn homogeneous_batch_has_no_nb_quota_and_preserves_first_payload() {
        let b = udp();
        let first = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        let mut batch = first;
        for _ in 1..4097 {
            batch.merge(&first).unwrap();
        }
        assert_eq!(batch.ip_len, 4097 * first.ip_len);
        assert_eq!(batch.payload_len, first.payload_len);
        assert_eq!(batch.capture_layout(), first.capture_layout());
        assert!(!batch.cacheable);
        let original = batch;
        let mut other = first;
        other.flow.source_port += 1;
        assert_eq!(batch.merge(&other), Err(ParseError::Malformed));
        assert_eq!(batch.ip_len, original.ip_len);
        assert_eq!(batch.payload_len, original.payload_len);
    }
    #[test]
    fn large_batch_bandwidth_is_64_bit_and_saturates_without_wrapping() {
        let b = udp();
        let first = parse(&b, b.len(), 14 + MAX_PAYLOAD, true).unwrap().unwrap();
        let mut batch = first;
        for _ in 1..8193 {
            batch.merge(&first).unwrap();
        }
        assert_eq!(batch.ip_len, 8193 * MAX_PAYLOAD as u64);
        assert!(batch.ip_len > u64::from(u32::MAX));
        assert_eq!(batch.payload_len as usize, MAX_PAYLOAD);
        batch.ip_len = u64::MAX;
        batch.merge(&first).unwrap();
        assert_eq!(batch.ip_len, u64::MAX);
    }
    #[test]
    fn host_send_normalizes_guest_endpoints_without_changing_capture() {
        let b = udp();
        let mut p = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
        let original = p;
        p.orient(NdisPath::Send);
        assert_eq!(p.connection.direction, Direction::Inbound);
        assert_eq!(p.connection.local_ip, p.flow.destination);
        assert_eq!(p.connection.remote_ip, p.flow.source);
        assert_eq!(p.connection.local_port, 53);
        assert_eq!(p.connection.remote_port, 1234);
        assert_eq!(p.payload_len, original.payload_len);
        assert_eq!(p.capture_layout(), original.capture_layout());
        assert_eq!(p.flow, original.flow);
        p.orient(NdisPath::Receive);
        assert_eq!(p.connection, original.connection);
    }
    #[test]
    fn replies_have_the_same_guest_tuple_for_ipv4_and_ipv6() {
        for ipv6 in [false, true] {
            let mut b = udp();
            let (source, destination, size, port) = if ipv6 {
                b = [0; 64];
                b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                b[14] = 0x60;
                b[18..20].copy_from_slice(&8u16.to_be_bytes());
                b[20] = 17;
                b[22] = 0x20;
                b[23] = 1;
                b[37] = 1;
                b[38] = 0x20;
                b[39] = 1;
                b[53] = 2;
                b[54..56].copy_from_slice(&1234u16.to_be_bytes());
                b[56..58].copy_from_slice(&53u16.to_be_bytes());
                b[58..60].copy_from_slice(&8u16.to_be_bytes());
                (22, 38, 16, 54)
            } else {
                (26, 30, 4, 34)
            };
            let mut outbound = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
            outbound.orient(NdisPath::Receive);
            assert_eq!(outbound.connection.direction, Direction::Outbound);
            for i in 0..size {
                b.swap(source + i, destination + i);
            }
            b.swap(port, port + 2);
            b.swap(port + 1, port + 3);
            let mut inbound = parse(&b, b.len(), b.len(), false).unwrap().unwrap();
            inbound.orient(NdisPath::Send);
            assert_eq!(inbound.connection.direction, Direction::Inbound);
            assert_eq!(inbound.connection.local_ip, outbound.connection.local_ip);
            assert_eq!(inbound.connection.remote_ip, outbound.connection.remote_ip);
            assert_eq!(
                inbound.connection.local_port,
                outbound.connection.local_port
            );
            assert_eq!(
                inbound.connection.remote_port,
                outbound.connection.remote_port
            );
            assert_ne!(inbound.flow.source, outbound.flow.source);
            assert_eq!(inbound.payload_len, outbound.payload_len);
        }
    }
    #[test]
    fn every_truncation_is_bounded() {
        let b = udp();
        for i in 0..b.len() {
            let _ = parse(&b[..i], i, i, false);
        }
        for i in 0..b.len() {
            let _ = parse(&b, i, b.len(), false);
        }
        assert!(parse(&b, 14, b.len(), false).is_err());
    }
    #[test]
    fn fragments_and_offload_cannot_seed_cache() {
        let mut b = udp();
        b[20] = 0x20;
        let p = parse(&b, 64, 64, false).unwrap().unwrap();
        assert!(!p.cacheable);
        assert_eq!(p.flow.destination_port, 0);
        b[20] = 0;
        assert!(!parse(&b, 64, 64, true).unwrap().unwrap().cacheable);
    }
    #[test]
    fn vlan_and_non_ip() {
        let b = udp();
        let mut v = [0; 68];
        v[..12].copy_from_slice(&b[..12]);
        v[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        v[14..16].copy_from_slice(&123u16.to_be_bytes());
        v[16..].copy_from_slice(&b[12..]);
        let p = parse(&v, 68, 68, false).unwrap().unwrap();
        assert_eq!(p.flow.l2_len, 18);
        assert_eq!(p.flow.destination_port, 53);
        v[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(parse(&v, 68, 68, false).unwrap().is_none());
    }
    #[test]
    fn ipv6_extensions_and_fragment() {
        let mut b = [0; 90];
        b[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        b[14] = 0x60;
        b[18..20].copy_from_slice(&16u16.to_be_bytes());
        b[20] = 0;
        b[54] = 17;
        b[62..64].copy_from_slice(&123u16.to_be_bytes());
        b[64..66].copy_from_slice(&53u16.to_be_bytes());
        b[66..68].copy_from_slice(&8u16.to_be_bytes());
        let p = parse(&b, 90, 90, false).unwrap().unwrap();
        assert!(p.cacheable);
        assert_eq!(p.flow.protocol, 17);
        b[20] = 44;
        assert!(!parse(&b, 90, 90, false).unwrap().unwrap().cacheable);
    }
    #[test]
    fn no_cache_from_untrusted_transport() {
        let b = udp();
        let p = parse(&b, 34, 64, false).unwrap().unwrap();
        assert!(!p.cacheable);
        assert_eq!(p.flow.source_port, 0);
    }
    #[test]
    fn malformed_lengths_are_rejected() {
        let mut b = udp();
        b[14] = 0x41;
        assert_eq!(parse(&b, 64, 64, false).unwrap_err(), ParseError::Malformed);
        b = udp();
        b[38..40].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse(&b, 64, 64, false).is_err());
        b = udp();
        b[16..18].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse(&b, 64, 64, false).is_err());
    }
}
