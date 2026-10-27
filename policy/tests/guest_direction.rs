use hyperv_policy::{
    engine::{Engine, Finish, Key, Submission, allocate_record},
    packet::{self, NdisPath, Packet},
};
use hyperv_protocol::{Direction, Verdict, connection_header_len};

fn sandbox_request(protocol: u8) -> Vec<u8> {
    let size = if protocol == 1 { 60u16 } else { 52 };
    let mut bytes = vec![0u8; 14 + usize::from(size)];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&size.to_be_bytes());
    bytes[23] = protocol;
    bytes[26..30].copy_from_slice(&[172, 28, 192, 8]);
    bytes[30..34].copy_from_slice(&[192, 168, 3, if protocol == 1 { 1 } else { 2 }]);
    if protocol == 1 {
        bytes[34] = 8;
    } else {
        bytes[34..36].copy_from_slice(&49714u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&1234u16.to_be_bytes());
        bytes[46] = 0x80;
        bytes[47] = 2;
    }
    bytes
}

fn reply(request: &[u8]) -> Vec<u8> {
    let mut bytes = request.to_vec();
    for i in 0..4 {
        bytes.swap(26 + i, 30 + i);
    }
    if bytes[23] == 1 {
        bytes[34] = 0;
    } else {
        bytes.swap(34, 36);
        bytes.swap(35, 37);
        bytes[47] = 0x12;
    }
    bytes
}

fn parse(bytes: &[u8], path: NdisPath) -> Packet {
    let mut packet = packet::parse(bytes, bytes.len(), bytes.len(), false)
        .unwrap()
        .unwrap();
    packet.orient(path);
    packet
}

fn engine() -> Box<Engine> {
    let mut engine = Box::new(Engine::new());
    assert!(engine.attach(1, 101));
    assert!(engine.restart(1));
    engine.connect();
    engine
}

fn capture(packet: &Packet, frame: &[u8]) -> Vec<u8> {
    let layout = packet.capture_layout().unwrap();
    let mut data = allocate_record(layout.record_len).unwrap();
    data[layout.frame_start..].copy_from_slice(&frame[..layout.frame_len]);
    data
}

fn submit(engine: &mut Engine, packet: Packet, path: NdisPath, token: usize, frame: &[u8]) -> u64 {
    let key = Key {
        adapter: 1,
        epoch: engine.epoch(1).unwrap(),
        path,
        vlan: 0,
        flow: packet.flow,
    };
    let data = capture(&packet, frame);
    let Submission::Pending(id) = engine.submit(key, packet, token, 0, 100, Some(data)) else {
        panic!("expected one pending NBL")
    };
    id
}

fn record(engine: &mut Engine, kind: u8) -> Vec<u8> {
    let mut bytes = [0u8; 4096];
    let count = engine.read(&mut bytes);
    let mut offset = 0;
    let mut found = None;
    while offset < count {
        let size = u32::from_le_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        if bytes[offset] == kind {
            assert!(found.is_none(), "unexpected duplicate record");
            found = Some(bytes[offset..offset + 5 + size].to_vec());
        }
        offset += 5 + size;
    }
    assert_eq!(offset, count);
    found.expect("expected wire record")
}

#[test]
fn ndis_ownership_path_is_not_public_direction() {
    assert_eq!(NdisPath::decode(0), Some(NdisPath::Send));
    assert_eq!(NdisPath::decode(1), Some(NdisPath::Receive));
    assert_eq!(NdisPath::decode(2), None);
    assert_eq!(NdisPath::decode(u32::MAX), None);
    assert_eq!(NdisPath::Send.direction() as u8, 1);
    assert_eq!(NdisPath::Receive.direction() as u8, 0);
}

#[test]
fn sandbox_ping_and_tcp_requests_are_outbound_replies_inbound() {
    for protocol in [1, 6] {
        let request = sandbox_request(protocol);
        let reply = reply(&request);
        let outgoing = parse(&request, NdisPath::decode(1).unwrap());
        let incoming = parse(&reply, NdisPath::decode(0).unwrap());
        assert_eq!(outgoing.connection.direction, Direction::Outbound);
        assert_eq!(incoming.connection.direction, Direction::Inbound);
        for (packet, original) in [(outgoing, request), (incoming, reply)] {
            let connection = packet.connection;
            assert_eq!(&connection.local_ip[..4], &[172, 28, 192, 8]);
            assert_eq!(
                &connection.remote_ip[..4],
                &[192, 168, 3, if protocol == 1 { 1 } else { 2 }]
            );
            assert_eq!(connection.local_port, if protocol == 1 { 0 } else { 49714 });
            assert_eq!(connection.remote_port, if protocol == 1 { 0 } else { 1234 });
            assert_eq!(connection.protocol, protocol);
            assert_eq!(packet.payload_len as usize, original.len() - 14);
            let data = capture(&packet, &original);
            assert_eq!(&data[connection_header_len(&connection)..], &original[14..]);
            assert_eq!(packet.cacheable, protocol == 6);
        }
    }
}

#[test]
fn guest_wire_direction_and_endpoints_survive_allow_and_drop() {
    for protocol in [1, 6] {
        for verdict in [Verdict::PermanentAccept, Verdict::PermanentDrop] {
            let request = sandbox_request(protocol);
            for (path, bytes, direction) in [
                (NdisPath::Receive, request.clone(), 0),
                (NdisPath::Send, reply(&request), 1),
            ] {
                // A fresh interface cache forces an event for each wire direction.
                let mut engine = engine();
                let packet = parse(&bytes, path);
                let id = submit(&mut engine, packet, path, 7, &bytes);
                let event = record(&mut engine, 1);
                assert_eq!(u64::from_le_bytes(event[5..13].try_into().unwrap()), id);
                assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), 101);
                assert_eq!(event[17], direction);
                assert_eq!(event[18], protocol);
                assert_eq!(&event[19..23], &[172, 28, 192, 8]);
                assert_eq!(&event[23..27], &packet.connection.remote_ip[..4]);
                assert_eq!(
                    u16::from_le_bytes(event[27..29].try_into().unwrap()),
                    packet.connection.local_port
                );
                assert_eq!(
                    u16::from_le_bytes(event[29..31].try_into().unwrap()),
                    packet.connection.remote_port
                );
                assert_eq!(&event[36..], &bytes[14..]);
                let action = engine.verdict(id, verdict, 101).unwrap();
                assert_eq!(action.token, 7);
                assert_eq!(
                    action.finish,
                    if verdict.allows() {
                        Finish::Allow
                    } else {
                        Finish::Drop
                    }
                );
            }
        }
    }
}

#[test]
fn tcp_reply_reuses_the_same_normalized_tuple_cache_entry() {
    for verdict in [Verdict::PermanentAccept, Verdict::PermanentDrop] {
        let mut engine = engine();
        let request = sandbox_request(6);
        let outgoing = parse(&request, NdisPath::Receive);
        let id = submit(&mut engine, outgoing, NdisPath::Receive, 1, &request);
        let _ = record(&mut engine, 1);
        engine.verdict(id, verdict, 101).unwrap();
        let response = reply(&request);
        let incoming = parse(&response, NdisPath::Send);
        let key = Key {
            adapter: 1,
            epoch: engine.epoch(1).unwrap(),
            path: NdisPath::Send,
            vlan: 0,
            flow: incoming.flow,
        };
        let action = engine.preflight(&key, &incoming, 2, 102).unwrap_err();
        assert_eq!(action.token, 2);
        assert_eq!(
            action.finish,
            if verdict.allows() {
                Finish::Allow
            } else {
                Finish::Drop
            }
        );
        assert_eq!(engine.stats().cache_hits, 1);
        assert!(!engine.has_events());
    }
}

#[test]
fn guest_bandwidth_uses_receive_for_tx_send_for_rx() {
    let mut engine = engine();
    let request = sandbox_request(6);
    let mut response = reply(&request);
    response.truncate(54);
    response[16..18].copy_from_slice(&40u16.to_be_bytes());
    response[46] = 0x50;
    for (path, bytes) in [(NdisPath::Receive, request), (NdisPath::Send, response)] {
        let packet = parse(&bytes, path);
        let id = submit(&mut engine, packet, path, 1, &bytes);
        assert_eq!(
            engine.verdict(id, Verdict::Accept, 101).unwrap().finish,
            Finish::Allow
        );
    }
    engine.bandwidth();
    let event = record(&mut engine, 5);
    assert_eq!(u32::from_le_bytes(event[6..10].try_into().unwrap()), 1);
    assert_eq!(&event[10..14], &[172, 28, 192, 8]);
    assert_eq!(u16::from_le_bytes(event[14..16].try_into().unwrap()), 49714);
    assert_eq!(&event[16..20], &[192, 168, 3, 2]);
    assert_eq!(u16::from_le_bytes(event[20..22].try_into().unwrap()), 1234);
    assert_eq!(u64::from_le_bytes(event[22..30].try_into().unwrap()), 52);
    assert_eq!(u64::from_le_bytes(event[30..38].try_into().unwrap()), 40);
}
