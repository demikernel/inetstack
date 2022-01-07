// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    collections::bytes::{Bytes, BytesMut},
    engine::Engine,
    file_table::FileDescriptor,
    protocols::{
        ip::{self},
        ipv4::{self},
        tcp::{
            operations::PushFuture,
            tests::{
                check_packet_data, check_packet_pure_ack,
                setup::{advance_clock, connection_setup},
            },
        },
    },
    runtime::Runtime,
    test_helpers::{self, TestRuntime},
};
use futures::task::noop_waker_ref;
use must_let::must_let;
use rand;
use std::{
    collections::VecDeque,
    convert::TryFrom,
    future::Future,
    num::Wrapping,
    ops::Add,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

//=============================================================================

/// Cooks a buffer.
fn cook_buffer(size: usize, stamp: Option<u8>) -> Bytes {
    let mut buf: BytesMut = BytesMut::zeroed(size).unwrap();
    for i in 0..size {
        buf[i] = stamp.unwrap_or(i as u8);
    }
    buf.freeze()
}

//=============================================================================

fn send_data(
    ctx: &mut Context,
    now: &mut Instant,
    receiver: &mut Engine<TestRuntime>,
    sender: &mut Engine<TestRuntime>,
    sender_fd: FileDescriptor,
    window_size: u16,
    seq_no: Wrapping<u32>,
    ack_num: Option<Wrapping<u32>>,
    bytes: Bytes,
) -> (Bytes, usize) {
    trace!(
        "====> push: {:?} -> {:?}",
        sender.rt().local_ipv4_addr(),
        receiver.rt().local_ipv4_addr()
    );

    // Push data.
    let mut push_future: PushFuture<TestRuntime> = sender.tcp_push(sender_fd, bytes.clone());

    let bytes: Bytes = sender.rt().pop_frame();
    let bufsize: usize = check_packet_data(
        bytes.clone(),
        sender.rt().local_link_addr(),
        receiver.rt().local_link_addr(),
        sender.rt().local_ipv4_addr(),
        receiver.rt().local_ipv4_addr(),
        window_size,
        seq_no,
        ack_num,
    );

    advance_clock(Some(receiver), Some(sender), now);

    // Push completes.
    must_let!(let Poll::Ready(Ok(())) = Future::poll(Pin::new(&mut push_future), ctx));

    trace!("====> push completed");

    (bytes, bufsize)
}

//=============================================================================

fn recv_data(
    ctx: &mut Context,
    receiver: &mut Engine<TestRuntime>,
    sender: &mut Engine<TestRuntime>,
    receiver_fd: FileDescriptor,
    bytes: Bytes,
) {
    trace!(
        "====> pop: {:?} -> {:?}",
        sender.rt().local_ipv4_addr(),
        receiver.rt().local_ipv4_addr()
    );

    // Pop data.
    let mut pop_future = receiver.tcp_pop(receiver_fd);
    receiver.receive(bytes).unwrap();

    // Pop completes
    must_let!(let Poll::Ready(Ok(_)) = Future::poll(Pin::new(&mut pop_future), ctx));

    trace!("====> pop completed");
}

//=============================================================================

fn recv_pure_ack(
    now: &mut Instant,
    sender: &mut Engine<TestRuntime>,
    receiver: &mut Engine<TestRuntime>,
    window_size: u16,
    seq_no: Wrapping<u32>,
) {
    trace!(
        "====> ack: {:?} -> {:?}",
        sender.rt().local_ipv4_addr(),
        receiver.rt().local_ipv4_addr()
    );

    advance_clock(Some(sender), Some(receiver), now);
    sender.rt().poll_scheduler();

    // Pop pure ACK
    if let Some(bytes) = sender.rt().pop_frame_unchecked() {
        check_packet_pure_ack(
            bytes.clone(),
            sender.rt().local_link_addr(),
            receiver.rt().local_link_addr(),
            sender.rt().local_ipv4_addr(),
            receiver.rt().local_ipv4_addr(),
            window_size,
            seq_no,
        );
        receiver.receive(bytes).unwrap();
    }
    trace!("====> ack completed");
}

//=============================================================================

fn send_recv(
    ctx: &mut Context,
    now: &mut Instant,
    server: &mut Engine<TestRuntime>,
    client: &mut Engine<TestRuntime>,
    server_fd: FileDescriptor,
    client_fd: FileDescriptor,
    window_size: u16,
    seq_no: Wrapping<u32>,
    bytes: Bytes,
) {
    let bufsize: usize = bytes.len();

    // Push data.
    let (bytes, _): (Bytes, usize) = send_data(
        ctx,
        now,
        server,
        client,
        client_fd,
        window_size,
        seq_no,
        None,
        bytes.clone(),
    );

    // Pop data.
    recv_data(ctx, server, client, server_fd, bytes.clone());

    // Pop pure ACK
    recv_pure_ack(
        now,
        server,
        client,
        window_size,
        seq_no.add(Wrapping(bufsize as u32)),
    );
}

//=============================================================================

fn send_recv_round(
    ctx: &mut Context,
    now: &mut Instant,
    server: &mut Engine<TestRuntime>,
    client: &mut Engine<TestRuntime>,
    server_fd: FileDescriptor,
    client_fd: FileDescriptor,
    window_size: u16,
    seq_no: Wrapping<u32>,
    bytes: Bytes,
) {
    // Push Data: Client -> Server
    let (bytes, bufsize): (Bytes, usize) = send_data(
        ctx,
        now,
        server,
        client,
        client_fd,
        window_size,
        seq_no,
        None,
        bytes.clone(),
    );

    // Pop data.
    recv_data(ctx, server, client, server_fd, bytes.clone());

    // Push Data: Server -> Client
    let bytes = cook_buffer(bufsize, None);
    let (bytes, _): (Bytes, usize) = send_data(
        ctx,
        now,
        client,
        server,
        server_fd,
        window_size,
        seq_no,
        Some(seq_no.add(Wrapping(bufsize as u32))),
        bytes.clone(),
    );

    // Pop data.
    recv_data(ctx, client, server, client_fd, bytes.clone());
}

//=============================================================================

fn connection_hangup(
    _ctx: &mut Context,
    now: &mut Instant,
    server: &mut Engine<TestRuntime>,
    client: &mut Engine<TestRuntime>,
    server_fd: FileDescriptor,
    client_fd: FileDescriptor,
) {
    // Send FIN: Client -> Server
    client.close(client_fd).unwrap();
    client.rt().poll_scheduler();
    let bytes: Bytes = client.rt().pop_frame();
    advance_clock(Some(server), Some(client), now);

    // ACK FIN: Server -> Client
    server.receive(bytes).unwrap();
    server.rt().poll_scheduler();
    let bytes: Bytes = server.rt().pop_frame();
    advance_clock(Some(server), Some(client), now);

    // Receive ACK FIN
    client.receive(bytes).unwrap();
    advance_clock(Some(server), Some(client), now);

    // Send FIN: Server -> Client
    server.close(server_fd).unwrap();
    server.rt().poll_scheduler();
    let bytes: Bytes = server.rt().pop_frame();
    advance_clock(Some(server), Some(client), now);

    // ACK FIN: Client -> Server
    client.receive(bytes).unwrap();
    client.rt().poll_scheduler();
    let bytes: Bytes = client.rt().pop_frame();
    advance_clock(Some(server), Some(client), now);

    // Receive ACK FIN
    server.receive(bytes).unwrap();

    advance_clock(Some(server), Some(client), now);

    client.rt().poll_scheduler();
    server.rt().poll_scheduler();
}

//=============================================================================

/// Tests one way communication. This should force the receiving peer to send
/// pure ACKs to the sender.
#[test]
pub fn test_send_recv_loop() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: Engine<TestRuntime> = test_helpers::new_bob2(now);
    let mut client: Engine<TestRuntime> = test_helpers::new_alice2(now);
    let window_scale: u8 = client.rt().tcp_options().window_scale();
    let max_window_size: u32 = (client.rt().tcp_options().receive_window_size() as u32)
        .checked_shl(window_scale as u32)
        .unwrap();

    let (server_fd, client_fd): (FileDescriptor, FileDescriptor) = connection_setup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        listen_port,
        listen_addr,
    );

    let bufsize: u32 = 64;
    let buf: Bytes = cook_buffer(bufsize as usize, None);

    for i in 0..((max_window_size + 1) / bufsize) {
        send_recv(
            &mut ctx,
            &mut now,
            &mut server,
            &mut client,
            server_fd,
            client_fd,
            max_window_size as u16,
            Wrapping(1 + i * bufsize),
            buf.clone(),
        );
    }
}

//=============================================================================

#[test]
pub fn test_send_recv_round_loop() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: Engine<TestRuntime> = test_helpers::new_bob2(now);
    let mut client: Engine<TestRuntime> = test_helpers::new_alice2(now);
    let window_scale: u8 = client.rt().tcp_options().window_scale();
    let max_window_size: u32 = (client.rt().tcp_options().receive_window_size() as u32)
        .checked_shl(window_scale as u32)
        .unwrap();

    let (server_fd, client_fd): (FileDescriptor, FileDescriptor) = connection_setup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        listen_port,
        listen_addr,
    );

    let bufsize: u32 = 64;
    let buf: Bytes = cook_buffer(bufsize as usize, None);

    for i in 0..((max_window_size + 1) / bufsize) {
        send_recv_round(
            &mut ctx,
            &mut now,
            &mut server,
            &mut client,
            server_fd,
            client_fd,
            max_window_size as u16,
            Wrapping(1 + i * bufsize),
            buf.clone(),
        );
    }
}

//=============================================================================

/// Tests one way communication, with some random transmission delay. This
/// should force the receiving peer to send pure ACKs to the sender, as well as
/// the sender side to trigger the RTO calculation logic.
#[test]
pub fn test_send_recv_with_delay() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: Engine<TestRuntime> = test_helpers::new_bob2(now);
    let mut client: Engine<TestRuntime> = test_helpers::new_alice2(now);
    let window_scale: u8 = client.rt().tcp_options().window_scale();
    let max_window_size: u32 = (client.rt().tcp_options().receive_window_size() as u32)
        .checked_shl(window_scale as u32)
        .unwrap();

    let (server_fd, client_fd): (FileDescriptor, FileDescriptor) = connection_setup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        listen_port,
        listen_addr,
    );

    let bufsize: u32 = 64;
    let buf: Bytes = cook_buffer(bufsize as usize, None);
    let mut recv_seq_no: Wrapping<u32> = Wrapping(1);
    let mut seq_no: Wrapping<u32> = Wrapping(1);
    let mut inflight = VecDeque::<Bytes>::new();

    for _ in 0..((max_window_size + 1) / bufsize) {
        // Push data.
        let (bytes, _): (Bytes, usize) = send_data(
            &mut ctx,
            &mut now,
            &mut server,
            &mut client,
            client_fd,
            max_window_size as u16,
            seq_no,
            None,
            buf.clone(),
        );

        seq_no = seq_no.add(Wrapping(bufsize));

        inflight.push_back(bytes);

        // Pop data oftentimes.
        if rand::random() {
            if let Some(bytes) = inflight.pop_front() {
                recv_data(&mut ctx, &mut server, &mut client, server_fd, bytes.clone());
                recv_seq_no = recv_seq_no.add(Wrapping(bufsize as u32));
            }
        }

        // Pop pure ACK
        recv_pure_ack(
            &mut now,
            &mut server,
            &mut client,
            max_window_size as u16,
            recv_seq_no,
        );
    }

    // Pop inflight packets.
    while let Some(bytes) = inflight.pop_front() {
        // Pop data.
        recv_data(&mut ctx, &mut server, &mut client, server_fd, bytes.clone());
        recv_seq_no = recv_seq_no.add(Wrapping(bufsize as u32));

        // Send pure ack.
        recv_pure_ack(
            &mut now,
            &mut server,
            &mut client,
            max_window_size as u16,
            recv_seq_no,
        );
    }
}

//=============================================================================

#[test]
fn test_connect_disconnect() {
    let mut ctx = Context::from_waker(noop_waker_ref());
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: ip::Port = ip::Port::try_from(80).unwrap();
    let listen_addr: ipv4::Endpoint = ipv4::Endpoint::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: Engine<TestRuntime> = test_helpers::new_bob2(now);
    let mut client: Engine<TestRuntime> = test_helpers::new_alice2(now);

    let (server_fd, client_fd): (FileDescriptor, FileDescriptor) = connection_setup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        listen_port,
        listen_addr,
    );

    connection_hangup(
        &mut ctx,
        &mut now,
        &mut server,
        &mut client,
        server_fd,
        client_fd,
    );
}
