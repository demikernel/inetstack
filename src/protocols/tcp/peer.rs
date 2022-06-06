// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//==============================================================================
// Imports
//==============================================================================

use super::{
    active_open::ActiveOpenSocket,
    established::EstablishedSocket,
    isn_generator::IsnGenerator,
    passive_open::PassiveSocket,
};
use crate::protocols::{
    arp::ArpPeer,
    ethernet2::{
        EtherType2,
        Ethernet2Header,
    },
    ip::{
        EphemeralPorts,
        IpProtocol,
    },
    ipv4::Ipv4Header,
    tcp::{
        established::ControlBlock,
        operations::{
            AcceptFuture,
            ConnectFuture,
            ConnectFutureState,
            PopFuture,
            PushFuture,
        },
        segment::{
            TcpHeader,
            TcpSegment,
        },
    },
};
use ::futures::channel::mpsc;
use ::libc::{
    EAGAIN,
    EBADF,
    EBADMSG,
    EBUSY,
    EINPROGRESS,
    EINVAL,
    ENOTCONN,
    ENOTSUP,
    EOPNOTSUPP,
};
use ::rand::{
    prelude::SmallRng,
    Rng,
    SeedableRng,
};
use ::runtime::{
    fail::Fail,
    memory::{
        Buffer,
        DataBuffer,
    },
    network::{
        config::TcpConfig,
        types::MacAddress,
        NetworkRuntime,
    },
    task::SchedulerRuntime,
    QDesc,
};
use ::std::{
    cell::{
        RefCell,
        RefMut,
    },
    collections::HashMap,
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    rc::Rc,
    task::{
        Context,
        Poll,
    },
    time::Duration,
};

#[cfg(feature = "profiler")]
use ::runtime::perftools::timer;

//==============================================================================
// Enumerations
//==============================================================================

enum Socket {
    Inactive { local: Option<SocketAddrV4> },
    Listening { local: SocketAddrV4 },
    Connecting { local: SocketAddrV4, remote: SocketAddrV4 },
    Established { local: SocketAddrV4, remote: SocketAddrV4 },
}

//==============================================================================
// Structures
//==============================================================================

pub struct Inner<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> {
    isn_generator: IsnGenerator,

    ephemeral_ports: EphemeralPorts,

    // FD -> local port
    sockets: HashMap<QDesc, Socket>,

    passive: HashMap<SocketAddrV4, PassiveSocket<RT>>,
    connecting: HashMap<(SocketAddrV4, SocketAddrV4), ActiveOpenSocket<RT>>,
    established: HashMap<(SocketAddrV4, SocketAddrV4), EstablishedSocket<RT>>,

    rt: RT,
    local_ipv4_addr: Ipv4Addr,
    local_link_addr: MacAddress,
    arp: ArpPeer<RT>,
    rng: Rc<RefCell<SmallRng>>,
    tcp_options: TcpConfig,

    dead_socket_tx: mpsc::UnboundedSender<QDesc>,
}

pub struct TcpPeer<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> {
    pub(super) inner: Rc<RefCell<Inner<RT>>>,
}

//==============================================================================
// Associated FUnctions
//==============================================================================

impl<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> TcpPeer<RT> {
    pub fn new(
        rt: RT,
        local_link_addr: MacAddress,
        local_ipv4_addr: Ipv4Addr,
        arp: ArpPeer<RT>,
        rng_seed: [u8; 32],
        tcp_options: TcpConfig,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let inner = Rc::new(RefCell::new(Inner::new(
            rt.clone(),
            local_link_addr,
            local_ipv4_addr,
            arp,
            rng_seed,
            tcp_options,
            tx,
            rx,
        )));
        Self { inner }
    }

    /// Opens a TCP socket.
    pub fn do_socket(&self, qd: QDesc) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("tcp::socket");
        let mut inner: RefMut<Inner<RT>> = self.inner.borrow_mut();
        match inner.sockets.contains_key(&qd) {
            false => {
                let socket: Socket = Socket::Inactive { local: None };
                inner.sockets.insert(qd, socket);
                Ok(())
            },
            true => return Err(Fail::new(EBUSY, "queue descriptor in use")),
        }
    }

    pub fn bind(&self, fd: QDesc, addr: SocketAddrV4) -> Result<(), Fail> {
        let mut inner = self.inner.borrow_mut();
        if addr.port() >= EphemeralPorts::first_private_port() {
            return Err(Fail::new(EBADMSG, "Port number in private port range"));
        }

        // Check if address is already bound.
        for (_, socket) in &inner.sockets {
            match socket {
                Socket::Inactive { local: Some(local) }
                | Socket::Listening { local }
                | Socket::Connecting { local, remote: _ }
                | Socket::Established { local, remote: _ }
                    if *local == addr =>
                {
                    return Err(Fail::new(libc::EADDRINUSE, "address already in use"))
                },
                _ => (),
            }
        }

        match inner.sockets.get_mut(&fd) {
            Some(Socket::Inactive { ref mut local }) => match *local {
                Some(_) => return Err(Fail::new(libc::EINVAL, "socket is already bound to an address")),
                None => {
                    *local = Some(addr);
                    Ok(())
                },
            },
            _ => Err(Fail::new(EBADF, "invalid queue descriptor")),
        }
    }

    pub fn receive(&self, ip_header: &Ipv4Header, buf: Box<dyn Buffer>) -> Result<(), Fail> {
        self.inner.borrow_mut().receive(ip_header, buf)
    }

    // Marks the target socket as passive.
    pub fn listen(&self, qd: QDesc, backlog: usize) -> Result<(), Fail> {
        let mut inner: RefMut<Inner<RT>> = self.inner.borrow_mut();

        // Get bound address while checking for several issues.
        let local: SocketAddrV4 = match inner.sockets.get_mut(&qd) {
            Some(Socket::Inactive { local: Some(local) }) => *local,
            Some(Socket::Listening { local: _ }) => return Err(Fail::new(libc::EINVAL, "socket is already listening")),
            Some(Socket::Inactive { local: None }) => {
                return Err(Fail::new(libc::EDESTADDRREQ, "socket is not bound to a local address"))
            },
            Some(Socket::Connecting { local: _, remote: _ }) => {
                return Err(Fail::new(libc::EINVAL, "socket is connecting"))
            },
            Some(Socket::Established { local: _, remote: _ }) => {
                return Err(Fail::new(libc::EINVAL, "socket is connected"))
            },
            _ => return Err(Fail::new(libc::EBADF, "invalid queue descriptor")),
        };

        // Check if there isn't a socket listening on this address/port pair.
        if inner.passive.contains_key(&local) {
            return Err(Fail::new(
                libc::EADDRINUSE,
                "another socket is already listening on the same address/port pair",
            ));
        }

        let nonce: u32 = inner.rng.borrow_mut().gen();
        let socket = PassiveSocket::new(
            local,
            backlog,
            inner.rt.clone(),
            inner.local_link_addr,
            inner.arp.clone(),
            inner.tcp_options.clone(),
            nonce,
        );
        assert!(inner.passive.insert(local, socket).is_none());
        inner.sockets.insert(qd, Socket::Listening { local });
        Ok(())
    }

    /// Accepts an incoming connection.
    pub fn do_accept(&self, qd: QDesc, new_qd: QDesc) -> AcceptFuture<RT> {
        AcceptFuture::new(qd, new_qd, self.inner.clone())
    }

    /// Handles an incoming connection.
    pub fn poll_accept(&self, qd: QDesc, new_qd: QDesc, ctx: &mut Context) -> Poll<Result<QDesc, Fail>> {
        let mut inner_: RefMut<Inner<RT>> = self.inner.borrow_mut();
        let inner: &mut Inner<RT> = &mut *inner_;

        let local: &SocketAddrV4 = match inner.sockets.get(&qd) {
            Some(Socket::Listening { local }) => local,
            Some(..) => return Poll::Ready(Err(Fail::new(EOPNOTSUPP, "socket not listening"))),
            None => return Poll::Ready(Err(Fail::new(EBADF, "bad file descriptor"))),
        };

        let passive: &mut PassiveSocket<RT> = inner.passive.get_mut(local).expect("sockets/local inconsistency");
        let cb: ControlBlock<RT> = match passive.poll_accept(ctx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(e)) => e,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };
        let established: EstablishedSocket<RT> = EstablishedSocket::new(cb, new_qd, inner.dead_socket_tx.clone());
        let key: (SocketAddrV4, SocketAddrV4) = (established.cb.get_local(), established.cb.get_remote());

        let socket: Socket = Socket::Established {
            local: established.cb.get_local(),
            remote: established.cb.get_remote(),
        };

        // TODO: Reset the connection if the following following check fails, instead of panicking.
        if inner.sockets.insert(new_qd, socket).is_some() {
            panic!("duplicate queue descriptor in sockets table");
        }

        // TODO: Reset the connection if the following following check fails, instead of panicking.
        if inner.established.insert(key, established).is_some() {
            panic!("duplicate queue descriptor in established sockets table");
        }

        Poll::Ready(Ok(new_qd))
    }

    pub fn connect(&self, fd: QDesc, remote: SocketAddrV4) -> ConnectFuture<RT> {
        let mut inner = self.inner.borrow_mut();

        let r = try {
            match inner.sockets.get_mut(&fd) {
                Some(Socket::Inactive { .. }) => (),
                _ => Err(Fail::new(EBADF, "invalid file descriptor"))?,
            }

            // TODO: We need to free these!
            let local_port = inner.ephemeral_ports.alloc()?;
            let local = SocketAddrV4::new(inner.local_ipv4_addr, local_port);

            let socket = Socket::Connecting { local, remote };
            inner.sockets.insert(fd, socket);

            let local_isn = inner.isn_generator.generate(&local, &remote);
            let key = (local, remote);
            let socket = ActiveOpenSocket::new(
                local_isn,
                local,
                remote,
                inner.rt.clone(),
                inner.local_link_addr,
                inner.arp.clone(),
                inner.tcp_options.clone(),
            );
            assert!(inner.connecting.insert(key, socket).is_none());
            fd
        };
        let state = match r {
            Ok(..) => ConnectFutureState::InProgress,
            Err(e) => ConnectFutureState::Failed(e),
        };
        ConnectFuture {
            fd,
            state,
            inner: self.inner.clone(),
        }
    }

    pub fn poll_recv(&self, fd: QDesc, ctx: &mut Context) -> Poll<Result<Box<dyn Buffer>, Fail>> {
        let inner = self.inner.borrow_mut();
        let key = match inner.sockets.get(&fd) {
            Some(Socket::Established { local, remote }) => (*local, *remote),
            Some(Socket::Connecting { .. }) => return Poll::Ready(Err(Fail::new(EINPROGRESS, "socket connecting"))),
            Some(Socket::Inactive { .. }) => return Poll::Ready(Err(Fail::new(EBADF, "socket inactive"))),
            Some(Socket::Listening { .. }) => return Poll::Ready(Err(Fail::new(ENOTCONN, "socket listening"))),
            None => return Poll::Ready(Err(Fail::new(EBADF, "bad queue descriptor"))),
        };
        match inner.established.get(&key) {
            Some(ref s) => s.poll_recv(ctx),
            None => Poll::Ready(Err(Fail::new(ENOTCONN, "connection not established"))),
        }
    }

    pub fn push(&self, fd: QDesc, buf: Box<dyn Buffer>) -> PushFuture {
        let err = match self.send(fd, buf) {
            Ok(()) => None,
            Err(e) => Some(e),
        };
        PushFuture { fd, err }
    }

    pub fn pop(&self, fd: QDesc) -> PopFuture<RT> {
        PopFuture {
            fd,
            inner: self.inner.clone(),
        }
    }

    fn send(&self, fd: QDesc, buf: Box<dyn Buffer>) -> Result<(), Fail> {
        let inner = self.inner.borrow_mut();
        let key = match inner.sockets.get(&fd) {
            Some(Socket::Established { local, remote }) => (*local, *remote),
            Some(..) => return Err(Fail::new(ENOTCONN, "connection not established")),
            None => return Err(Fail::new(EBADF, "bad queue descriptor")),
        };
        match inner.established.get(&key) {
            Some(ref s) => s.send(buf),
            None => Err(Fail::new(ENOTCONN, "connection not established")),
        }
    }

    /// Closes a TCP socket.
    pub fn do_close(&self, qd: QDesc) -> Result<(), Fail> {
        let mut inner: RefMut<Inner<RT>> = self.inner.borrow_mut();

        match inner.sockets.remove(&qd) {
            Some(Socket::Established { local, remote }) => {
                let key: (SocketAddrV4, SocketAddrV4) = (local, remote);
                match inner.established.get(&key) {
                    Some(ref s) => s.close()?,
                    None => return Err(Fail::new(ENOTCONN, "connection not established")),
                }
            },

            Some(..) => return Err(Fail::new(ENOTSUP, "close not implemented for listening sockets")),
            None => return Err(Fail::new(EBADF, "bad queue descriptor")),
        }

        Ok(())
    }

    pub fn remote_mss(&self, fd: QDesc) -> Result<usize, Fail> {
        let inner = self.inner.borrow();
        let key = match inner.sockets.get(&fd) {
            Some(Socket::Established { local, remote }) => (*local, *remote),
            Some(..) => return Err(Fail::new(ENOTCONN, "connection not established")),
            None => return Err(Fail::new(EBADF, "bad queue descriptor")),
        };
        match inner.established.get(&key) {
            Some(ref s) => Ok(s.remote_mss()),
            None => Err(Fail::new(ENOTCONN, "connection not established")),
        }
    }

    pub fn current_rto(&self, fd: QDesc) -> Result<Duration, Fail> {
        let inner = self.inner.borrow();
        let key = match inner.sockets.get(&fd) {
            Some(Socket::Established { local, remote }) => (*local, *remote),
            Some(..) => return Err(Fail::new(ENOTCONN, "connection not established")),
            None => return Err(Fail::new(EBADF, "bad queue descriptor")),
        };
        match inner.established.get(&key) {
            Some(ref s) => Ok(s.current_rto()),
            None => Err(Fail::new(ENOTCONN, "connection not established")),
        }
    }

    pub fn endpoints(&self, fd: QDesc) -> Result<(SocketAddrV4, SocketAddrV4), Fail> {
        let inner = self.inner.borrow();
        let key = match inner.sockets.get(&fd) {
            Some(Socket::Established { local, remote }) => (*local, *remote),
            Some(..) => return Err(Fail::new(ENOTCONN, "connection not established")),
            None => return Err(Fail::new(EBADF, "bad queue descriptor")),
        };
        match inner.established.get(&key) {
            Some(ref s) => Ok(s.endpoints()),
            None => Err(Fail::new(ENOTCONN, "connection not established")),
        }
    }
}

impl<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> Inner<RT> {
    fn new(
        rt: RT,
        local_link_addr: MacAddress,
        local_ipv4_addr: Ipv4Addr,
        arp: ArpPeer<RT>,
        rng_seed: [u8; 32],
        tcp_options: TcpConfig,
        dead_socket_tx: mpsc::UnboundedSender<QDesc>,
        _dead_socket_rx: mpsc::UnboundedReceiver<QDesc>,
    ) -> Self {
        let mut rng: SmallRng = SmallRng::from_seed(rng_seed);
        let ephemeral_ports: EphemeralPorts = EphemeralPorts::new(&mut rng);
        let nonce: u32 = rng.gen();
        Self {
            isn_generator: IsnGenerator::new(nonce),
            ephemeral_ports,
            sockets: HashMap::new(),
            passive: HashMap::new(),
            connecting: HashMap::new(),
            established: HashMap::new(),
            rt,
            local_link_addr,
            local_ipv4_addr,
            arp,
            rng: Rc::new(RefCell::new(rng)),
            tcp_options,
            dead_socket_tx,
        }
    }

    fn receive(&mut self, ip_hdr: &Ipv4Header, buf: Box<dyn Buffer>) -> Result<(), Fail> {
        let (mut tcp_hdr, data) = TcpHeader::parse(ip_hdr, buf, self.tcp_options.get_rx_checksum_offload())?;
        debug!("TCP received {:?}", tcp_hdr);
        let local = SocketAddrV4::new(ip_hdr.get_dest_addr(), tcp_hdr.dst_port);
        let remote = SocketAddrV4::new(ip_hdr.get_src_addr(), tcp_hdr.src_port);

        if remote.ip().is_broadcast() || remote.ip().is_multicast() || remote.ip().is_unspecified() {
            return Err(Fail::new(EINVAL, "invalid address type"));
        }
        let key = (local, remote);

        if let Some(s) = self.established.get(&key) {
            debug!("Routing to established connection: {:?}", key);
            s.receive(&mut tcp_hdr, data);
            return Ok(());
        }
        if let Some(s) = self.connecting.get_mut(&key) {
            debug!("Routing to connecting connection: {:?}", key);
            s.receive(&tcp_hdr);
            return Ok(());
        }
        let (local, _) = key;
        if let Some(s) = self.passive.get_mut(&local) {
            debug!("Routing to passive connection: {:?}", local);
            return s.receive(ip_hdr, &tcp_hdr);
        }

        // The packet isn't for an open port; send a RST segment.
        debug!("Sending RST for {:?}, {:?}", local, remote);
        self.send_rst(&local, &remote)?;
        Ok(())
    }

    fn send_rst(&mut self, local: &SocketAddrV4, remote: &SocketAddrV4) -> Result<(), Fail> {
        // TODO: Make this work pending on ARP resolution if needed.
        let remote_link_addr = self
            .arp
            .try_query(remote.ip().clone())
            .ok_or(Fail::new(EINVAL, "detination not in ARP cache"))?;

        let mut tcp_hdr = TcpHeader::new(local.port(), remote.port());
        tcp_hdr.rst = true;

        let segment = TcpSegment {
            ethernet2_hdr: Ethernet2Header::new(remote_link_addr, self.local_link_addr, EtherType2::Ipv4),
            ipv4_hdr: Ipv4Header::new(local.ip().clone(), remote.ip().clone(), IpProtocol::TCP),
            tcp_hdr,
            data: Box::new(DataBuffer::empty()),
            tx_checksum_offload: self.tcp_options.get_rx_checksum_offload(),
        };
        self.rt.transmit(segment);

        Ok(())
    }

    pub(super) fn poll_connect_finished(&mut self, fd: QDesc, context: &mut Context) -> Poll<Result<(), Fail>> {
        let key = match self.sockets.get(&fd) {
            Some(Socket::Connecting { local, remote }) => (*local, *remote),
            Some(..) => return Poll::Ready(Err(Fail::new(EAGAIN, "socket not connecting"))),
            None => return Poll::Ready(Err(Fail::new(EBADF, "bad queue descriptor"))),
        };

        let result = {
            let socket = match self.connecting.get_mut(&key) {
                Some(s) => s,
                None => return Poll::Ready(Err(Fail::new(EAGAIN, "socket not connecting"))),
            };
            match socket.poll_result(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            }
        };
        self.connecting.remove(&key);

        let cb = result?;
        let socket = EstablishedSocket::new(cb, fd, self.dead_socket_tx.clone());
        assert!(self.established.insert(key, socket).is_none());
        let (local, remote) = key;
        self.sockets.insert(fd, Socket::Established { local, remote });

        Poll::Ready(Ok(()))
    }
}
