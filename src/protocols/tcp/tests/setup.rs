// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    collections::bytes::{Bytes, BytesMut},
    engine::Engine,
    fail::Fail,
    file_table::FileDescriptor,
    protocols::{
        ethernet2::{EtherType2, Ethernet2Header, MacAddress},
        ip::{self, Port},
        ipv4::{self, Ipv4Header},
        tcp::{
            operations::{AcceptFuture, ConnectFuture},
            segment::{TcpHeader, TcpSegment},
        },
    },
    runtime::{PacketBuf, Runtime, RuntimeBuf},
    test_helpers::{self, TestRuntime},
};
use futures::task::noop_waker_ref;
use must_let::must_let;
use std::{
    convert::TryFrom,
    future::Future,
    net::Ipv4Addr,
    num::Wrapping,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

//=============================================================================

//tests connection timeout.
#[test]
fn test_connection_timeout() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup client.
    let mut client = test_helpers::new_alice2(now);
    let nretries: usize = client.rt().tcp_options().handshake_retries();
    let timeout: Duration = client.rt().tcp_options().handshake_timeout();

    // T(0) -> T(1)
    advance_clock(None, Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, mut connect_future, bytes): (FileDescriptor, ConnectFuture<TestRuntime>, Bytes) =
        connection_setup_listen_syn_sent(&mut client, listen_addr);

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    );

    for _ in 0..nretries {
        for _ in 0..timeout.as_secs() {
            advance_clock(None, Some(&mut client), &mut now);
        }
        client.rt().poll_scheduler();
    }

    must_let!(let Poll::Ready(Err(Fail::Timeout{})) = Future::poll(Pin::new(&mut connect_future), &mut ctx));
}

//=============================================================================

/// Refuse a connection.
#[test]
fn test_refuse_connection_early_rst() {
    let _ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server = test_helpers::new_bob2(now);
    let mut client = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: AcceptFuture<TestRuntime> = connection_setup_closed_listen(&mut server, listen_addr);

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (FileDescriptor, ConnectFuture<TestRuntime>, Bytes) =
        connection_setup_listen_syn_sent(&mut client, listen_addr);

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone());
    let segment: TcpSegment<<TestRuntime as Runtime>::Buf> = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: tcp_header.ack,
            psh: tcp_header.psh,
            rst: true,
            syn: tcp_header.syn,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: Bytes::empty(),
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: Bytes = serialize_segment(segment);

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    must_let!(let Err(Fail::Malformed{ details : "Invalid flags"}) = server.receive(buf));
}

//=============================================================================

/// Refuse a connection.
#[test]
fn test_refuse_connection_early_ack() {
    let _ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server = test_helpers::new_bob2(now);
    let mut client = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: AcceptFuture<TestRuntime> = connection_setup_closed_listen(&mut server, listen_addr);

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (FileDescriptor, ConnectFuture<TestRuntime>, Bytes) =
        connection_setup_listen_syn_sent(&mut client, listen_addr);

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone());
    let segment: TcpSegment<<TestRuntime as Runtime>::Buf> = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: true,
            psh: tcp_header.psh,
            rst: tcp_header.rst,
            syn: tcp_header.syn,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: Bytes::empty(),
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: Bytes = serialize_segment(segment);

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    must_let!(let Err(Fail::Malformed{ details : "Invalid flags"}) = server.receive(buf));
}

//=============================================================================

/// Tests connection refuse due to missing syn.
#[test]
fn test_refuse_connection_missing_syn() {
    let _ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server = test_helpers::new_bob2(now);
    let mut client = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: AcceptFuture<TestRuntime> = connection_setup_closed_listen(&mut server, listen_addr);

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (FileDescriptor, ConnectFuture<TestRuntime>, Bytes) =
        connection_setup_listen_syn_sent(&mut client, listen_addr);

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    );

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone());
    let segment: TcpSegment<<TestRuntime as Runtime>::Buf> = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: tcp_header.ack,
            psh: tcp_header.psh,
            rst: tcp_header.rst,
            syn: false,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: Bytes::empty(),
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: Bytes = serialize_segment(segment);

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    must_let!(let Err(Fail::Malformed{ details : "Invalid flags"}) = server.receive(buf));
}

//=============================================================================

/// Extracts headers of a TCP packet.
fn extract_headers(bytes: Bytes) -> (Ethernet2Header, Ipv4Header, TcpHeader) {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();

    return (eth2_header, ipv4_header, tcp_header);
}

//=============================================================================

/// Serializes a TCP segment.
fn serialize_segment(pkt: TcpSegment<Bytes>) -> Bytes {
    let header_size: usize = pkt.header_size();
    let body_size: usize = pkt.body_size();
    let mut buf: BytesMut = BytesMut::zeroed(header_size + body_size).unwrap();
    pkt.write_header(&mut buf[..header_size]);
    if let Some(body) = pkt.take_body() {
        buf[header_size..].copy_from_slice(&body[..]);
    }
    buf.freeze()
}

//=============================================================================

/// Triggers LISTEN -> SYN_SENT state transition.
fn connection_setup_listen_syn_sent(
    client: &mut Engine<TestRuntime>,
    listen_addr: ipv4::Endpoint,
) -> (FileDescriptor, ConnectFuture<TestRuntime>, Bytes) {
    // Issue CONNECT operation.
    let client_fd: FileDescriptor = client.tcp_socket();
    let connect_future: ConnectFuture<TestRuntime> = client.tcp_connect(client_fd, listen_addr);

    // SYN_SENT state.
    client.rt().poll_scheduler();
    let bytes: Bytes = client.rt().pop_frame();

    (client_fd, connect_future, bytes)
}

/// Triggers CLOSED -> LISTEN state transition.
fn connection_setup_closed_listen(
    server: &mut Engine<TestRuntime>,
    listen_addr: ipv4::Endpoint,
) -> AcceptFuture<TestRuntime> {
    // Issue ACCEPT operation.
    let socket_fd: u32 = server.tcp_socket();
    server.tcp_bind(socket_fd, listen_addr).unwrap();
    server.tcp_listen(socket_fd, 1).unwrap();
    let accept_future: AcceptFuture<TestRuntime> = server.tcp_accept(socket_fd);

    // LISTEN state.
    server.rt().poll_scheduler();

    accept_future
}

/// Triggers LISTEN -> SYN_RCVD state transition.
fn connection_setup_listen_syn_rcvd(server: &mut Engine<TestRuntime>, bytes: Bytes) -> Bytes {
    // SYN_RCVD state.
    server.receive(bytes).unwrap();
    server.rt().poll_scheduler();
    server.rt().pop_frame()
}

/// Triggers SYN_SENT -> ESTABLISHED state transition.
fn connection_setup_syn_sent_established(client: &mut Engine<TestRuntime>, bytes: Bytes) -> Bytes {
    client.receive(bytes).unwrap();
    client.rt().poll_scheduler();
    client.rt().pop_frame()
}

/// Triggers SYN_RCVD -> ESTABLISHED state transition.
fn connection_setup_sync_rcvd_established(server: &mut Engine<TestRuntime>, bytes: Bytes) {
    server.receive(bytes).unwrap();
    server.rt().poll_scheduler();
}

/// Checks for a pure SYN packet. This packet is sent by the sender side (active
/// open peer) when transitioning from the LISTEN to the SYN_SENT state.
fn check_packet_pure_syn(
    bytes: Bytes,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    dst_port: Port,
) {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    assert_eq!(eth2_header.src_addr, eth2_src_addr);
    assert_eq!(eth2_header.dst_addr, eth2_dst_addr);
    assert_eq!(eth2_header.ether_type, EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    assert_eq!(ipv4_header.src_addr, ipv4_src_addr);
    assert_eq!(ipv4_header.dst_addr, ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    assert_eq!(tcp_header.dst_port, dst_port);
    assert_eq!(tcp_header.seq_num, Wrapping(0));
    assert_eq!(tcp_header.syn, true);
}

/// Checks for a SYN+ACK packet. This packet is sent by the receiver side
/// (passive open peer) when transitioning from the LISTEN to the SYN_RCVD state.
fn check_packet_syn_ack(
    bytes: Bytes,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    src_port: Port,
) {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    assert_eq!(eth2_header.src_addr, eth2_src_addr);
    assert_eq!(eth2_header.dst_addr, eth2_dst_addr);
    assert_eq!(eth2_header.ether_type, EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    assert_eq!(ipv4_header.src_addr, ipv4_src_addr);
    assert_eq!(ipv4_header.dst_addr, ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    assert_eq!(tcp_header.src_port, src_port);
    assert_eq!(tcp_header.ack_num, Wrapping(1));
    assert_eq!(tcp_header.seq_num, Wrapping(0));
    assert_eq!(tcp_header.syn, true);
    assert_eq!(tcp_header.ack, true);
}

/// Checks for a pure ACK on a SYN+ACK packet. This packet is sent by the sender
/// side (active open peer) when transitioning from the SYN_SENT state to the
/// ESTABLISHED state.
fn check_packet_pure_ack_on_syn_ack(
    bytes: Bytes,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    dst_port: Port,
) {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    assert_eq!(eth2_header.src_addr, eth2_src_addr);
    assert_eq!(eth2_header.dst_addr, eth2_dst_addr);
    assert_eq!(eth2_header.ether_type, EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    assert_eq!(ipv4_header.src_addr, ipv4_src_addr);
    assert_eq!(ipv4_header.dst_addr, ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    assert_eq!(tcp_header.dst_port, dst_port);
    assert_eq!(tcp_header.seq_num, Wrapping(1));
    assert_eq!(tcp_header.ack_num, Wrapping(1));
    assert_eq!(tcp_header.ack, true);
}

/// Advances clock by one second.
pub fn advance_clock(
    server: Option<&mut Engine<TestRuntime>>,
    client: Option<&mut Engine<TestRuntime>>,
    now: &mut Instant,
) {
    *now += Duration::from_secs(1);
    if let Some(server) = server {
        server.rt().advance_clock(*now);
    }
    if let Some(client) = client {
        client.rt().advance_clock(*now);
    }
}

/// Runs 3-way connection setup.
pub fn connection_setup(
    ctx: &mut Context,
    now: &mut Instant,
    server: &mut Engine<TestRuntime>,
    client: &mut Engine<TestRuntime>,
    listen_port: ip::Port,
    listen_addr: ipv4::Endpoint,
) -> (FileDescriptor, FileDescriptor) {
    // Server: LISTEN state at T(0).
    let mut accept_future: AcceptFuture<TestRuntime> =
        connection_setup_closed_listen(server, listen_addr);

    // T(0) -> T(1)
    advance_clock(Some(server), Some(client), now);

    // Client: SYN_SENT state at T(1).
    let (client_fd, mut connect_future, mut bytes): (
        FileDescriptor,
        ConnectFuture<TestRuntime>,
        Bytes,
    ) = connection_setup_listen_syn_sent(client, listen_addr);

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    );

    // T(1) -> T(2)
    advance_clock(Some(server), Some(client), now);

    // Server: SYN_RCVD state at T(2).
    bytes = connection_setup_listen_syn_rcvd(server, bytes);

    // Sanity check packet.
    check_packet_syn_ack(
        bytes.clone(),
        test_helpers::BOB_MAC,
        test_helpers::ALICE_MAC,
        test_helpers::BOB_IPV4,
        test_helpers::ALICE_IPV4,
        listen_port,
    );

    // T(2) -> T(3)
    advance_clock(Some(server), Some(client), now);

    // Client: ESTABLISHED at T(3).
    bytes = connection_setup_syn_sent_established(client, bytes);

    // Sanity check sent packet.
    check_packet_pure_ack_on_syn_ack(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    );
    // T(3) -> T(4)
    advance_clock(Some(server), Some(client), now);

    // Server: ESTABLISHED at T(4).
    connection_setup_sync_rcvd_established(server, bytes);

    must_let!(let Poll::Ready(Ok(server_fd)) = Future::poll(Pin::new(&mut accept_future), ctx));
    must_let!(let Poll::Ready(Ok(())) = Future::poll(Pin::new(&mut connect_future), ctx));

    (server_fd, client_fd)
}

/// Tests basic 3-way connection setup.
#[test]
fn test_good_connect() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server = test_helpers::new_bob2(now);
    let mut client = test_helpers::new_alice2(now);

    let (_, _): (FileDescriptor, FileDescriptor) = connection_setup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        listen_port,
        listen_addr,
    );
}
