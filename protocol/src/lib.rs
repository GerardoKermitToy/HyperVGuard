#![no_std]

// Explicit byte protocol, deliberately independent of Rust/C structure layout.
pub const VERSION: [u8; 4] = [0, 3, 2, 0];
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const CONNECTION_V4_HEADER: usize = 36;
pub const CONNECTION_V6_HEADER: usize = 60;
pub const MAX_RECORD: usize = CONNECTION_V6_HEADER + MAX_PAYLOAD;
pub const MAX_LOG_RECORD: usize = 512;
pub const IOCTL_VERSION: u32 = ctl_code(0x800);
pub const IOCTL_SHUTDOWN: u32 = ctl_code(0x801);
// Four-byte little-endian count of running NDIS filter modules; no input.
pub const IOCTL_FILTERED_DEVICE_COUNT: u32 = ctl_code(0x802);
// No input; bounded attached-module snapshot, including paused modules. This
// additive diagnostic has its own schema version, not an event-wire change.
pub const IOCTL_ADAPTER_INFO: u32 = ctl_code(0x803);
pub const ADAPTER_INFO_VERSION: u32 = 1;
pub const ADAPTER_INFO_HEADER_SIZE: usize = 16;
pub const ADAPTER_INFO_ENTRY_SIZE: usize = 1760;
pub const ADAPTER_INFO_MAX_ADAPTERS: usize = 32;
pub const ADAPTER_INFO_NAME_CAPACITY: usize = 256;
pub const ADAPTER_INFO_MAC_CAPACITY: usize = 32;
pub const ADAPTER_INFO_MAX_SIZE: usize =
    ADAPTER_INFO_HEADER_SIZE + ADAPTER_INFO_MAX_ADAPTERS * ADAPTER_INFO_ENTRY_SIZE;
pub const ADAPTER_RUNNING: u32 = 0x01;
pub const ADAPTER_GENERAL_VALID: u32 = 0x02;
pub const ADAPTER_CONNECTOR_VALID: u32 = 0x04;
pub const ADAPTER_INSTANCE_NAME_TRUNCATED: u32 = 0x08;
pub const ADAPTER_BASE_NAME_TRUNCATED: u32 = 0x10;
pub const ADAPTER_FILTER_NAME_TRUNCATED: u32 = 0x20;
pub const ADAPTER_LINK_STATE_VALID: u32 = 0x40;
pub const ADAPTER_PAUSE_VALID: u32 = 0x80;
const fn ctl_code(function: u32) -> u32 {
    (40000 << 16) | (3 << 14) | (function << 2)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Accept = 2,
    PermanentAccept = 3,
    Block = 4,
    PermanentBlock = 5,
    Drop = 6,
    PermanentDrop = 7,
}
impl Verdict {
    pub fn decode(value: u8) -> Option<Self> {
        Some(match value {
            2 => Self::Accept,
            3 => Self::PermanentAccept,
            4 => Self::Block,
            5 => Self::PermanentBlock,
            6 => Self::Drop,
            7 => Self::PermanentDrop,
            _ => return None,
        })
    }
    pub const fn allows(self) -> bool {
        matches!(self, Self::Accept | Self::PermanentAccept)
    }
    pub const fn permanent(self) -> bool {
        matches!(
            self,
            Self::PermanentAccept | Self::PermanentBlock | Self::PermanentDrop
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Shutdown,
    Verdict { id: u64, verdict: Verdict },
    ClearCache,
    GetLogs,
    GetBandwidth,
    MemoryStats,
    CleanEnded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Unsupported,
    BufferTooSmall,
}

// Validate the ENTIRE write before applying any command. This also bounds batches.
pub fn validate_commands(mut bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(Error::Malformed);
    }
    while !bytes.is_empty() {
        let (_, rest) = next_command(bytes)?;
        bytes = rest;
    }
    Ok(())
}
pub fn next_command(bytes: &[u8]) -> Result<(Command, &[u8]), Error> {
    let kind = *bytes.first().ok_or(Error::Malformed)?;
    let size = match kind {
        0 | 4..=8 => 1,
        1 => 10,
        _ => return Err(Error::Unsupported),
    };
    if bytes.len() < size {
        return Err(Error::Malformed);
    }
    let command = match kind {
        0 => Command::Shutdown,
        1 => Command::Verdict {
            id: u64::from_le_bytes(bytes[1..9].try_into().map_err(|_| Error::Malformed)?),
            verdict: Verdict::decode(bytes[9]).ok_or(Error::Unsupported)?,
        },
        4 => Command::ClearCache,
        5 => Command::GetLogs,
        6 => Command::GetBandwidth,
        7 => Command::MemoryStats,
        8 => Command::CleanEnded,
        _ => return Err(Error::Unsupported),
    };
    Ok((command, &bytes[size..]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Outbound = 0,
    Inbound = 1,
}
impl Direction {
    pub const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Outbound),
            1 => Some(Self::Inbound),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub direction: Direction,
    pub ipv6: bool,
    pub protocol: u8,
    pub local_ip: [u8; 16],
    pub remote_ip: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
}
impl Connection {
    pub const EMPTY: Self = Self {
        direction: Direction::Outbound,
        ipv6: false,
        protocol: 0,
        local_ip: [0; 16],
        remote_ip: [0; 16],
        local_port: 0,
        remote_port: 0,
    };
}

pub struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}
impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(Error::BufferTooSmall)?;
        let dst = self
            .out
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
    pub fn u8(&mut self, n: u8) -> Result<(), Error> {
        self.bytes(&[n])
    }
    pub fn u16(&mut self, n: u16) -> Result<(), Error> {
        self.bytes(&n.to_le_bytes())
    }
    pub fn u32(&mut self, n: u32) -> Result<(), Error> {
        self.bytes(&n.to_le_bytes())
    }
    pub fn u64(&mut self, n: u64) -> Result<(), Error> {
        self.bytes(&n.to_le_bytes())
    }
    pub fn len(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
}

pub const fn connection_header_len(c: &Connection) -> usize {
    if c.ipv6 {
        CONNECTION_V6_HEADER
    } else {
        CONNECTION_V4_HEADER
    }
}

// Encode only the small prefix: callers can copy the full packet directly into
// its final nonpaged allocation before publishing the event under the policy lock.
pub fn encode_connection_header(
    out: &mut [u8],
    id: u64,
    interface_index: u32,
    c: &Connection,
    payload_len: usize,
) -> Result<usize, Error> {
    if payload_len > MAX_PAYLOAD {
        return Err(Error::Malformed);
    }
    let addr_len = if c.ipv6 { 16 } else { 4 };
    let size = connection_header_len(c) - 5 + payload_len;
    let mut w = Writer::new(out);
    w.u8(if c.ipv6 { 2 } else { 1 })?;
    w.u32(size as u32)?;
    w.u64(id)?;
    w.u32(interface_index)?;
    w.u8(c.direction as u8)?; // Guest side, not host NDIS send/receive.
    w.u8(c.protocol)?;
    w.bytes(&c.local_ip[..addr_len])?;
    w.bytes(&c.remote_ip[..addr_len])?;
    w.u16(c.local_port)?;
    w.u16(c.remote_port)?;
    w.u8(3)?;
    w.u32(payload_len as u32)?;
    Ok(w.len())
}

pub fn encode_connection(
    out: &mut [u8],
    id: u64,
    interface_index: u32,
    c: &Connection,
    payload: &[u8],
) -> Result<usize, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::Malformed);
    }
    let len = connection_header_len(c) + payload.len();
    if out.len() < len {
        return Err(Error::BufferTooSmall);
    }
    let start = encode_connection_header(out, id, interface_index, c, payload.len())?;
    out[start..len].copy_from_slice(payload);
    Ok(len)
}
pub fn encode_log(out: &mut [u8], severity: u8, message: &str) -> Result<usize, Error> {
    if message.len() > MAX_LOG_RECORD - 6 {
        return Err(Error::Malformed);
    }
    let mut w = Writer::new(out);
    w.u8(0)?;
    w.u32(1 + message.len() as u32)?;
    w.u8(severity)?;
    w.bytes(message.as_bytes())?;
    Ok(w.len())
}
pub fn encode_bandwidth(out: &mut [u8], c: &Connection, tx: u64, rx: u64) -> Result<usize, Error> {
    let n = if c.ipv6 { 16 } else { 4 };
    let mut w = Writer::new(out);
    w.u8(if c.ipv6 { 6 } else { 5 })?;
    w.u32((5 + n * 2 + 4 + 16) as u32)?;
    w.u8(c.protocol)?;
    w.u32(1)?;
    w.bytes(&c.local_ip[..n])?;
    w.u16(c.local_port)?;
    w.bytes(&c.remote_ip[..n])?;
    w.u16(c.remote_port)?;
    w.u64(tx)?;
    w.u64(rx)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    #[test]
    fn ioctl_codes_are_stable() {
        assert_eq!(IOCTL_VERSION, 0x9c40_e000);
        assert_eq!(IOCTL_SHUTDOWN, 0x9c40_e004);
        assert_eq!(IOCTL_FILTERED_DEVICE_COUNT, 0x9c40_e008);
        assert_eq!(IOCTL_ADAPTER_INFO, 0x9c40_e00c);
        assert_eq!(ADAPTER_INFO_MAX_SIZE, 56_336);
        assert_eq!(
            ADAPTER_INFO_ENTRY_SIZE,
            224 + 3 * 2 * ADAPTER_INFO_NAME_CAPACITY
        );
        assert_eq!(
            ADAPTER_RUNNING
                | ADAPTER_GENERAL_VALID
                | ADAPTER_CONNECTOR_VALID
                | ADAPTER_INSTANCE_NAME_TRUNCATED
                | ADAPTER_BASE_NAME_TRUNCATED
                | ADAPTER_FILTER_NAME_TRUNCATED
                | ADAPTER_LINK_STATE_VALID
                | ADAPTER_PAUSE_VALID,
            0xff
        );
    }
    #[test]
    fn exact_v4_abi_without_process_id() {
        let mut c = Connection::EMPTY;
        c.protocol = 17;
        c.local_ip[..4].copy_from_slice(&[10, 0, 0, 1]);
        c.remote_ip[..4].copy_from_slice(&[10, 0, 0, 2]);
        c.local_port = 0x1234;
        c.remote_port = 53;
        let mut b = [0xff; 64];
        let n = encode_connection(&mut b, 0x0102030405060708, 0x12345678, &c, &[0x45, 0]).unwrap();
        assert_eq!(n, 38);
        assert_eq!(
            &b[..n],
            &[
                1, 33, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 0x78, 0x56, 0x34, 0x12, 0, 17, 10, 0, 0, 1,
                10, 0, 0, 2, 0x34, 0x12, 53, 0, 3, 2, 0, 0, 0, 0x45, 0,
            ]
        );
        assert_eq!(connection_header_len(&c), CONNECTION_V4_HEADER);
    }
    #[test]
    fn exact_v6_and_bandwidth_sizes() {
        let mut c = Connection::EMPTY;
        c.ipv6 = true;
        let mut b = [0; 128];
        assert_eq!(encode_connection(&mut b, 1, 0x12345678, &c, &[]), Ok(60));
        assert_eq!(b[0], 2);
        assert_eq!(b[1], 55);
        c.direction = Direction::Inbound;
        assert_eq!(encode_connection(&mut b, 1, 0x12345678, &c, &[]), Ok(60));
        assert_eq!(&b[13..17], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(b[17], 1);
        assert_eq!(b[55], 3);
        assert_eq!(&b[56..60], &[0; 4]);
        assert_eq!(encode_bandwidth(&mut b, &c, 123, 456), Ok(62));
        assert_eq!(&b[..10], &[6, 57, 0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(u64::from_le_bytes(b[46..54].try_into().unwrap()), 123);
        assert_eq!(u64::from_le_bytes(b[54..62].try_into().unwrap()), 456);
        assert_eq!(Direction::decode(2), None);
    }
    #[test]
    fn full_payloads_are_not_truncated_at_256_or_65536_bytes() {
        for ipv6 in [false, true] {
            let mut c = Connection::EMPTY;
            c.ipv6 = ipv6;
            for size in [0, 257, 1500, 65535, 65536, 65575, MAX_PAYLOAD] {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let prefix = connection_header_len(&c);
                let mut out = vec![0; prefix + size];
                assert_eq!(
                    encode_connection(&mut out, 19, 0x12345678, &c, &payload),
                    Ok(out.len())
                );
                assert_eq!(
                    u32::from_le_bytes(out[1..5].try_into().unwrap()) as usize,
                    out.len() - 5
                );
                assert_eq!(
                    u32::from_le_bytes(out[prefix - 4..prefix].try_into().unwrap()) as usize,
                    size
                );
                assert_eq!(&out[prefix..], &payload);
            }
        }
    }
    #[test]
    fn encoding_the_header_preserves_the_full_packet() {
        for ipv6 in [false, true] {
            let mut c = Connection::EMPTY;
            c.ipv6 = ipv6;
            let prefix = connection_header_len(&c);
            let mut out = vec![0xa5; prefix + 65575];
            assert_eq!(
                encode_connection_header(&mut out, 27, 0x12345678, &c, 65575),
                Ok(prefix)
            );
            assert!(out[prefix..].iter().all(|b| *b == 0xa5));
        }
    }
    #[test]
    fn invalid_capture_lengths_do_not_produce_partial_records() {
        let c = Connection::EMPTY;
        let too_large = vec![0; MAX_PAYLOAD + 1];
        let mut out = [0xa5; 64];
        assert_eq!(
            encode_connection(&mut out, 1, 0x12345678, &c, &too_large),
            Err(Error::Malformed)
        );
        assert_eq!(out, [0xa5; 64]);
        assert_eq!(
            encode_connection_header(&mut out, 1, 0x12345678, &c, MAX_PAYLOAD + 1),
            Err(Error::Malformed)
        );
        assert_eq!(out, [0xa5; 64]);
        assert_eq!(
            encode_connection(&mut out[..37], 1, 0x12345678, &c, &[0; 2]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(out, [0xa5; 64]);
        assert_eq!(VERSION, [0, 3, 2, 0]);
    }
    #[test]
    fn verdicts_are_identical_but_redirects_not_supported() {
        for v in 2..=7 {
            assert_eq!(Verdict::decode(v).unwrap() as u8, v);
        }
        for v in [0, 1, 8, 9, 10, 11, 255] {
            assert!(Verdict::decode(v).is_none());
        }
        let b = [1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 4, 5, 6, 7, 8];
        assert_eq!(validate_commands(&b), Ok(()));
        assert_eq!(validate_commands(&b[..9]), Err(Error::Malformed));
    }
    #[test]
    fn validate_complete_batch_before_side_effects() {
        assert_eq!(validate_commands(&[4, 99]), Err(Error::Unsupported));
        assert_eq!(validate_commands(&[4, 2]), Err(Error::Unsupported));
        assert_eq!(validate_commands(&[4, 3]), Err(Error::Unsupported));
        assert_eq!(
            validate_commands(&[0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 8]),
            Err(Error::Unsupported)
        );
        assert_eq!(validate_commands(&[4, 1, 2]), Err(Error::Malformed));
        assert!(validate_commands(&[]).is_err());
        assert_eq!(
            encode_log(&mut [0; 8], 3, "hello"),
            Err(Error::BufferTooSmall)
        );
    }
}
