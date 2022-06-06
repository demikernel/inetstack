// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::protocols::{
    arp::ArpPeer,
    ethernet2::{
        EtherType2,
        Ethernet2Header,
    },
    tcp::operations::{
        AcceptFuture,
        ConnectFuture,
        PopFuture,
        PushFuture,
    },
    udp::UdpPopFuture,
    Peer,
};
use ::libc::EBADMSG;
use ::runtime::{
    fail::Fail,
    memory::Buffer,
    network::{
        types::MacAddress,
        NetworkRuntime,
    },
    queue::IoQueueTable,
    task::SchedulerRuntime,
    QDesc,
    QType,
};
use ::std::{
    collections::HashMap,
    future::Future,
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    time::Duration,
};

pub struct Engine<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> {
    rt: RT,
    pub arp: ArpPeer<RT>,
    pub ipv4: Peer<RT>,
    pub file_table: IoQueueTable,
}

impl<RT: SchedulerRuntime + NetworkRuntime + Clone + 'static> Engine<RT> {
    pub fn new(rt: RT) -> Result<Self, Fail> {
        let now = rt.now();
        let file_table = IoQueueTable::new();
        let arp = ArpPeer::new(now, rt.clone(), rt.arp_options())?;
        let rng_seed: [u8; 32] = [0; 32];
        let ipv4 = Peer::new(rt.clone(), arp.clone(), rng_seed);
        Ok(Engine {
            rt,
            arp,
            ipv4,
            file_table,
        })
    }

    pub fn rt(&mut self) -> &mut RT {
        &mut self.rt
    }

    pub fn receive(&mut self, bytes: Box<dyn Buffer>) -> Result<(), Fail> {
        let (header, payload) = Ethernet2Header::parse(bytes)?;
        debug!("Engine received {:?}", header);
        if self.rt.local_link_addr() != header.dst_addr() && !header.dst_addr().is_broadcast() {
            return Err(Fail::new(EBADMSG, "physical destination address mismatch"));
        }
        match header.ether_type() {
            EtherType2::Arp => self.arp.receive(payload),
            EtherType2::Ipv4 => self.ipv4.receive(payload),
            EtherType2::Ipv6 => Ok(()), // Ignore for now.
        }
    }

    pub fn ipv4_ping(
        &mut self,
        dest_ipv4_addr: Ipv4Addr,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<Duration, Fail>> {
        self.ipv4.ping(dest_ipv4_addr, timeout)
    }

    pub fn udp_pushto(&self, fd: QDesc, buf: Box<dyn Buffer>, to: SocketAddrV4) -> Result<(), Fail> {
        self.ipv4.udp.do_pushto(fd, buf, to)
    }

    pub fn udp_pop(&mut self, fd: QDesc) -> UdpPopFuture {
        self.ipv4.udp.do_pop(fd)
    }

    pub fn udp_socket(&mut self) -> Result<QDesc, Fail> {
        let fd = self.file_table.alloc(QType::UdpSocket.into());
        self.ipv4.udp.do_socket(fd).unwrap();
        Ok(fd)
    }

    pub fn udp_bind(&mut self, socket_fd: QDesc, endpoint: SocketAddrV4) -> Result<(), Fail> {
        self.ipv4.udp.do_bind(socket_fd, endpoint)
    }

    pub fn udp_close(&mut self, socket_fd: QDesc) -> Result<(), Fail> {
        self.ipv4.udp.do_close(socket_fd)
    }

    pub fn tcp_socket(&mut self) -> Result<QDesc, Fail> {
        let fd = self.file_table.alloc(QType::TcpSocket.into());
        self.ipv4.tcp.do_socket(fd).unwrap();
        Ok(fd)
    }

    pub fn tcp_connect(&mut self, socket_fd: QDesc, remote_endpoint: SocketAddrV4) -> ConnectFuture<RT> {
        self.ipv4.tcp.connect(socket_fd, remote_endpoint)
    }

    pub fn tcp_bind(&mut self, socket_fd: QDesc, endpoint: SocketAddrV4) -> Result<(), Fail> {
        self.ipv4.tcp.bind(socket_fd, endpoint)
    }

    pub fn tcp_accept(&mut self, fd: QDesc) -> AcceptFuture<RT> {
        let newfd = self.file_table.alloc(QType::TcpSocket.into());
        self.ipv4.tcp.do_accept(fd, newfd)
    }

    pub fn tcp_push(&mut self, socket_fd: QDesc, buf: Box<dyn Buffer>) -> PushFuture {
        self.ipv4.tcp.push(socket_fd, buf)
    }

    pub fn tcp_pop(&mut self, socket_fd: QDesc) -> PopFuture<RT> {
        self.ipv4.tcp.pop(socket_fd)
    }

    pub fn tcp_close(&mut self, socket_fd: QDesc) -> Result<(), Fail> {
        self.ipv4.tcp.do_close(socket_fd)
    }

    pub fn tcp_listen(&mut self, socket_fd: QDesc, backlog: usize) -> Result<(), Fail> {
        self.ipv4.tcp.listen(socket_fd, backlog)
    }

    pub fn arp_query(&self, ipv4_addr: Ipv4Addr) -> impl Future<Output = Result<MacAddress, Fail>> {
        self.arp.query(ipv4_addr)
    }

    pub fn tcp_mss(&self, handle: QDesc) -> Result<usize, Fail> {
        self.ipv4.tcp_mss(handle)
    }

    pub fn tcp_rto(&self, handle: QDesc) -> Result<Duration, Fail> {
        self.ipv4.tcp_rto(handle)
    }

    pub fn export_arp_cache(&self) -> HashMap<Ipv4Addr, MacAddress> {
        self.arp.export_cache()
    }
}
