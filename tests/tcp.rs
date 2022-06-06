// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![feature(new_uninit)]

mod common;

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::common::{
    arp,
    libos::*,
    ALICE_IPV4,
    ALICE_MAC,
    BOB_IPV4,
    BOB_MAC,
    PORT_BASE,
};
use ::crossbeam_channel::{
    self,
    Receiver,
    Sender,
};
use ::inetstack::{
    operations::OperationResult,
    InetStack,
};
use ::runtime::{
    memory::{
        Buffer,
        DataBuffer,
    },
    QDesc,
    QToken,
};
use ::std::{
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    thread::{
        self,
        JoinHandle,
    },
};

//======================================================================================================================
// Open/Close Passive Socket
//======================================================================================================================

/// Tests if a passive socket may be successfully opened and closed.
#[test]
fn tcp_connection_setup() {
    let (tx, rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, tx, rx, arp());

    let port: u16 = PORT_BASE;
    let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

    // Open and close a connection.
    let sockqd: QDesc = safe_socket(&mut libos);
    safe_bind(&mut libos, sockqd, local);
    safe_listen(&mut libos, sockqd);
    safe_close_passive(&mut libos, sockqd);
}

//======================================================================================================================
// Establish Connection
//======================================================================================================================

/// Tests if data can be successfully established.
#[test]
fn tcp_establish_connection() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());

        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);

        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Close connection.
        safe_close_active(&mut libos, sockqd);
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Push
//======================================================================================================================

/// Tests if data can be pushed.
#[test]
fn tcp_push_remote() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());

        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Pop data.
        let qt: QToken = safe_pop(&mut libos, qd);
        let (qd, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Pop(_, _) => (),
            _ => panic!("pop() has has failed {:?}", qr),
        }

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Cook some data.
        let bytes: Box<dyn Buffer> = DummyLibOS::cook_data(32);

        // Push data.
        let qt: QToken = safe_push2(&mut libos, sockqd, &bytes);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Push => (),
            _ => panic!("push() has failed"),
        }

        // Close connection.
        safe_close_active(&mut libos, sockqd);
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Bad Socket
//======================================================================================================================

/// Tests for bad socket creation.
#[test]
fn tcp_bad_socket() {
    let (tx, rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, tx, rx, arp());

    let domains: Vec<libc::c_int> = vec![
        libc::AF_ALG,
        libc::AF_APPLETALK,
        libc::AF_ASH,
        libc::AF_ATMPVC,
        libc::AF_ATMSVC,
        libc::AF_AX25,
        libc::AF_BLUETOOTH,
        libc::AF_BRIDGE,
        libc::AF_CAIF,
        libc::AF_CAN,
        libc::AF_DECnet,
        libc::AF_ECONET,
        libc::AF_IB,
        libc::AF_IEEE802154,
        // libc::AF_INET,
        libc::AF_INET6,
        libc::AF_IPX,
        libc::AF_IRDA,
        libc::AF_ISDN,
        libc::AF_IUCV,
        libc::AF_KEY,
        libc::AF_LLC,
        libc::AF_LOCAL,
        libc::AF_MPLS,
        libc::AF_NETBEUI,
        libc::AF_NETLINK,
        libc::AF_NETROM,
        libc::AF_NFC,
        libc::AF_PACKET,
        libc::AF_PHONET,
        libc::AF_PPPOX,
        libc::AF_RDS,
        libc::AF_ROSE,
        libc::AF_ROUTE,
        libc::AF_RXRPC,
        libc::AF_SECURITY,
        libc::AF_SNA,
        libc::AF_TIPC,
        libc::AF_UNIX,
        libc::AF_UNSPEC,
        libc::AF_VSOCK,
        libc::AF_WANPIPE,
        libc::AF_X25,
        libc::AF_XDP,
    ];

    let scoket_types: Vec<libc::c_int> = vec![
        libc::SOCK_DCCP,
        // libc::SOCK_DGRAM,
        libc::SOCK_PACKET,
        libc::SOCK_RAW,
        libc::SOCK_RDM,
        libc::SOCK_SEQPACKET,
        // libc::SOCK_STREAM,
    ];

    // Invalid domain.
    for d in domains {
        match libos.socket(d, libc::SOCK_STREAM, 0) {
            Err(e) if e.errno == libc::ENOTSUP => (),
            _ => panic!("invalid call to socket() should fail with ENOTSUP"),
        };
    }

    // Invalid socket tpe.
    for t in scoket_types {
        match libos.socket(libc::AF_INET, t, 0) {
            Err(e) if e.errno == libc::ENOTSUP => (),
            _ => panic!("invalid call to socket() should fail with ENOTSUP"),
        };
    }
}

//======================================================================================================================
// Bad Bind
//======================================================================================================================

/// Test bad calls for `bind()`.
#[test]
fn tcp_bad_bind() {
    let (tx, rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, tx, rx, arp());

    let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, PORT_BASE);
    let local2: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, PORT_BASE + 1);

    // Invalid queue descriptor.
    match libos.bind(QDesc::from(0), local) {
        Err(e) if e.errno == libc::EBADF => (),
        _ => panic!("invalid call to bind() should fail with EBADF"),
    };

    // Bind socket multiple times.
    let sockqd: QDesc = safe_socket(&mut libos);
    safe_bind(&mut libos, sockqd, local);
    match libos.bind(sockqd, local2) {
        Err(e) if e.errno == libc::EINVAL => (),
        Err(e) => panic!("bind() failed with unexpected error code ({:?})", e),
        Ok(_) => panic!("bind() socket multiple times should fail with EINVAL"),
    };
    safe_close_passive(&mut libos, sockqd);

    // Bind sockets to same address.
    let sockqd_a: QDesc = safe_socket(&mut libos);
    let sockqd_b: QDesc = safe_socket(&mut libos);
    safe_bind(&mut libos, sockqd_a, local);
    match libos.bind(sockqd_b, local) {
        Err(e) if e.errno == libc::EADDRINUSE => (),
        Err(e) => panic!("bind() failed with unexpected error code ({:?})", e),
        Ok(_) => panic!("bind() multiple sockets to the same address should fail with EADDRINUSE"),
    };
    safe_close_passive(&mut libos, sockqd_a);
    safe_close_passive(&mut libos, sockqd_b);
}

//======================================================================================================================
// Bad Listen
//======================================================================================================================

/// Tests bad calls for `listen()`.
#[test]
fn tcp_bad_listen() {
    let (tx, rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, tx, rx, arp());

    let port: u16 = PORT_BASE;
    let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

    // Invalid queue descriptor.
    match libos.listen(QDesc::from(0), 8) {
        Err(e) if e.errno == libc::EBADF => (),
        _ => panic!("invalid call to listen() should fail with EBADF"),
    };

    // Invalid backlog length
    let sockqd: QDesc = safe_socket(&mut libos);
    safe_bind(&mut libos, sockqd, local);
    match libos.listen(sockqd, 0) {
        Err(e) if e.errno == libc::EINVAL => (),
        _ => panic!("invalid call to listen() should fail with EINVAL"),
    };
    safe_close_passive(&mut libos, sockqd);

    // Listen on an already listening socket.
    let sockqd: QDesc = safe_socket(&mut libos);
    safe_bind(&mut libos, sockqd, local);
    safe_listen(&mut libos, sockqd);
    match libos.listen(sockqd, 16) {
        Err(e) if e.errno == libc::EINVAL => (),
        _ => panic!("listen() called on an already listening socket should fail with EINVAL"),
    };
    safe_close_passive(&mut libos, sockqd);

    // TODO: Add unit test for "Listen on an in-use address/port pair." (see issue #178).

    // Listen on unbound socket.
    let sockqd: QDesc = safe_socket(&mut libos);
    match libos.listen(sockqd, 16) {
        Err(e) if e.errno == libc::EDESTADDRREQ => (),
        Err(e) => panic!("listen() to unbound address should fail with EDESTADDRREQ {:?}", e),
        _ => panic!("should fail"),
    };
    safe_close_passive(&mut libos, sockqd);
}

//======================================================================================================================
// Bad Accept
//======================================================================================================================

/// Tests bad calls for `accept()`.
#[test]
fn tcp_bad_accept() {
    let (tx, rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, tx, rx, arp());

    // Invalid queue descriptor.
    match libos.accept(QDesc::from(0)) {
        Err(e) if e.errno == libc::EBADF => (),
        _ => panic!("invalid call to accept() should fail with EBADF"),
    };
}

//======================================================================================================================
// Bad Accept
//======================================================================================================================

/// Tests if data can be successfully established.
#[test]
fn tcp_bad_connect() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());
        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Bad queue descriptor.
        match libos.connect(QDesc::from(0), remote) {
            Err(e) if e.errno == libc::EBADF => (),
            _ => panic!("invalid call to connect() should fail with EBADF"),
        };

        // Bad endpoint.
        let bad_remote: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, bad_remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => panic!("connect() should have failed"),
            _ => (),
        }

        // Close connection.
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Close connection.
        safe_close_active(&mut libos, sockqd);
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Bad Close
//======================================================================================================================

/// Tests if bad calls t `close()`.
#[test]
fn tcp_bad_close() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());

        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Close bad queue descriptor.
        match libos.close(QDesc::from(2)) {
            Ok(_) => panic!("close() invalid file descriptir should fail"),
            Err(_) => (),
        };

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);

        // Double close queue descriptor.
        match libos.close(qd) {
            Ok(_) => panic!("double close() should fail"),
            Err(_) => (),
        };
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Close bad queue descriptor.
        match libos.close(QDesc::from(2)) {
            Ok(_) => panic!("close() invalid queue descriptor should fail"),
            Err(_) => (),
        };

        // Close connection.
        safe_close_active(&mut libos, sockqd);

        // Double close queue descriptor.
        match libos.close(sockqd) {
            Ok(_) => panic!("double close() should fail"),
            Err(_) => (),
        };
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Bad Push
//======================================================================================================================

/// Tests bad calls to `push()`.
#[test]
fn tcp_bad_push() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());

        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Pop data.
        let qt: QToken = safe_pop(&mut libos, qd);
        let (qd, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Pop(_, _) => (),
            _ => panic!("pop() has has failed {:?}", qr),
        }

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Cook some data.
        let bytes: Box<dyn Buffer> = DummyLibOS::cook_data(32);

        // Push to bad socket.
        match libos.push2(QDesc::from(2), &bytes) {
            Ok(_) => panic!("push2() to bad socket should fail."),
            Err(_) => (),
        };

        // Push bad data to socket.
        let zero_bytes: [u8; 0] = [];
        match libos.push2(sockqd, &DataBuffer::from_slice(&zero_bytes)) {
            Ok(_) => panic!("push2() zero-length slice should fail."),
            Err(_) => (),
        };

        // Push data.
        let qt: QToken = safe_push2(&mut libos, sockqd, &bytes);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Push => (),
            _ => panic!("push() has failed"),
        }

        // Close connection.
        safe_close_active(&mut libos, sockqd);
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Bad Pop
//======================================================================================================================

/// Tests bad calls to `pop()`.
#[test]
fn tcp_bad_pop() {
    let (alice_tx, alice_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();
    let (bob_tx, bob_rx): (Sender<DataBuffer>, Receiver<DataBuffer>) = crossbeam_channel::unbounded();

    let alice: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(ALICE_MAC, ALICE_IPV4, alice_tx, bob_rx, arp());

        let port: u16 = PORT_BASE;
        let local: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        safe_bind(&mut libos, sockqd, local);
        safe_listen(&mut libos, sockqd);
        let qt: QToken = safe_accept(&mut libos, sockqd);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        let qd: QDesc = match qr {
            OperationResult::Accept(qd) => qd,
            _ => panic!("accept() has failed"),
        };

        // Pop from bad socket.
        match libos.pop(QDesc::from(2)) {
            Ok(_) => panic!("pop() form bad socket should fail."),
            Err(_) => (),
        };

        // Pop data.
        let qt: QToken = safe_pop(&mut libos, qd);
        let (qd, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Pop(_, _) => (),
            _ => panic!("pop() has has failed {:?}", qr),
        }

        // Close connection.
        safe_close_active(&mut libos, qd);
        safe_close_passive(&mut libos, sockqd);
    });

    let bob: JoinHandle<()> = thread::spawn(move || {
        let mut libos: InetStack = DummyLibOS::new(BOB_MAC, BOB_IPV4, bob_tx, alice_rx, arp());

        let port: u16 = PORT_BASE;
        let remote: SocketAddrV4 = SocketAddrV4::new(ALICE_IPV4, port);

        // Open connection.
        let sockqd: QDesc = safe_socket(&mut libos);
        let qt: QToken = safe_connect(&mut libos, sockqd, remote);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Connect => (),
            _ => panic!("connect() has failed"),
        }

        // Cook some data.
        let bytes: Box<dyn Buffer> = DummyLibOS::cook_data(32);

        // Push data.
        let qt: QToken = safe_push2(&mut libos, sockqd, &bytes);
        let (_, qr): (QDesc, OperationResult) = safe_wait2(&mut libos, qt);
        match qr {
            OperationResult::Push => (),
            _ => panic!("push() has failed"),
        }

        // Close connection.
        safe_close_active(&mut libos, sockqd);
    });

    alice.join().unwrap();
    bob.join().unwrap();
}

//======================================================================================================================
// Standalone Functions
//======================================================================================================================

/// Safe call to `socket()`.
fn safe_socket(libos: &mut InetStack) -> QDesc {
    match libos.socket(libc::AF_INET, libc::SOCK_STREAM, 0) {
        Ok(sockqd) => sockqd,
        Err(e) => panic!("failed to create socket: {:?}", e),
    }
}

/// Safe call to `connect()`.
fn safe_connect(libos: &mut InetStack, sockqd: QDesc, remote: SocketAddrV4) -> QToken {
    match libos.connect(sockqd, remote) {
        Ok(qt) => qt,
        Err(e) => panic!("failed to establish connection: {:?}", e),
    }
}

/// Safe call to `bind()`.
fn safe_bind(libos: &mut InetStack, sockqd: QDesc, local: SocketAddrV4) {
    match libos.bind(sockqd, local) {
        Ok(_) => (),
        Err(e) => panic!("bind() failed: {:?}", e),
    };
}

/// Safe call to `listen()`.
fn safe_listen(libos: &mut InetStack, sockqd: QDesc) {
    match libos.listen(sockqd, 8) {
        Ok(_) => (),
        Err(e) => panic!("listen() failed: {:?}", e),
    };
}

/// Safe call to `accept()`.
fn safe_accept(libos: &mut InetStack, sockqd: QDesc) -> QToken {
    match libos.accept(sockqd) {
        Ok(qt) => qt,
        Err(e) => panic!("accept() failed: {:?}", e),
    }
}

/// Safe call to `pop()`.
fn safe_pop(libos: &mut InetStack, qd: QDesc) -> QToken {
    match libos.pop(qd) {
        Ok(qt) => qt,
        Err(e) => panic!("pop() failed: {:?}", e),
    }
}

/// Safe call to `push2()`
fn safe_push2(libos: &mut InetStack, sockqd: QDesc, bytes: &[u8]) -> QToken {
    match libos.push2(sockqd, bytes) {
        Ok(qt) => qt,
        Err(e) => panic!("failed to push: {:?}", e),
    }
}

/// Safe call to `wait2()`.
fn safe_wait2(libos: &mut InetStack, qt: QToken) -> (QDesc, OperationResult) {
    match libos.wait2(qt) {
        Ok((qd, qr)) => (qd, qr),
        Err(e) => panic!("operation failed: {:?}", e.cause),
    }
}

/// Safe call to `close()` on passive socket.
fn safe_close_passive(libos: &mut InetStack, sockqd: QDesc) {
    match libos.close(sockqd) {
        Ok(_) => panic!("close() on listening socket should have failed (this is a known bug)"),
        Err(_) => (),
    };
}

/// Safe call to `close()` on active socket.
fn safe_close_active(libos: &mut InetStack, qd: QDesc) {
    match libos.close(qd) {
        Ok(_) => (),
        Err(_) => panic!("close() on passive socket has failed"),
    };
}
