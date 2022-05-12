// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//==============================================================================
// Imports
//==============================================================================

use super::{
    datagram::{
        UdpDatagram,
        UdpHeader,
    },
    futures::UdpPopFuture,
    queue::{
        SharedQueue,
        SharedQueueSlot,
    },
};
use crate::{
    futures::FutureOperation,
    protocols::{
        arp::ArpPeer,
        ethernet2::{
            EtherType2,
            Ethernet2Header,
        },
        ip::IpProtocol,
        ipv4::{
            Ipv4Endpoint,
            Ipv4Header,
        },
    },
};
use ::futures::FutureExt;
use ::libc::{
    EADDRINUSE,
    EBADF,
    EEXIST,
    ENOTCONN,
};
use ::runtime::{
    fail::Fail,
    memory::Buffer,
    network::types::{
        Ipv4Addr,
        MacAddress,
    },
    scheduler::SchedulerHandle,
    QDesc,
    Runtime,
};
use ::std::collections::HashMap;

#[cfg(feature = "profiler")]
use ::perftools::timer;

//==============================================================================
// Structures
//==============================================================================

/// UDP Peer
pub struct UdpPeer<RT: Runtime> {
    /// Underlying runtime.
    rt: RT,
    /// Underlying ARP peer.
    arp: ArpPeer<RT>,
    /// Opened sockets.
    sockets: HashMap<QDesc, Option<Ipv4Endpoint>>,
    /// Bound sockets.
    bound: HashMap<Ipv4Endpoint, SharedQueue<SharedQueueSlot<Box<dyn Buffer>>>>,
    /// Queue of unset datagrams. This is shared across fast/slow paths.
    send_queue: SharedQueue<SharedQueueSlot<Box<dyn Buffer>>>,
    /// Local link address.
    local_link_addr: MacAddress,
    /// Local IPv4 address.
    local_ipv4_addr: Ipv4Addr,
    /// Offload checksum to hardware?
    checksum_offload: bool,
    /// Handler to background co-routines. Don't drop this.
    _handle: SchedulerHandle,
}

//==============================================================================
// Associate Functions
//==============================================================================

/// Associate functions for [UdpPeer].
impl<RT: Runtime> UdpPeer<RT> {
    /// Creates a Udp peer.
    pub fn new(
        rt: RT,
        local_link_addr: MacAddress,
        local_ipv4_addr: Ipv4Addr,
        offload_checksum: bool,
        arp: ArpPeer<RT>,
    ) -> Self {
        let send_queue: SharedQueue<SharedQueueSlot<Box<dyn Buffer>>> =
            SharedQueue::<SharedQueueSlot<Box<dyn Buffer>>>::new();
        let future = Self::background_sender(
            rt.clone(),
            local_ipv4_addr,
            local_link_addr,
            offload_checksum,
            arp.clone(),
            send_queue.clone(),
        );
        let handle: SchedulerHandle = rt.spawn(FutureOperation::Background::<RT>(future.boxed_local()));
        Self {
            rt,
            arp,
            sockets: HashMap::new(),
            bound: HashMap::new(),
            send_queue,
            local_link_addr,
            local_ipv4_addr,
            checksum_offload: offload_checksum,
            _handle: handle,
        }
    }

    /// Asynchronously send unsent datagrams to remote peer.
    async fn background_sender(
        rt: RT,
        local_ipv4_addr: Ipv4Addr,
        local_link_addr: MacAddress,
        offload_checksum: bool,
        arp: ArpPeer<RT>,
        mut rx: SharedQueue<SharedQueueSlot<Box<dyn Buffer>>>,
    ) {
        loop {
            // Grab next unsent datagram.
            match rx.pop().await {
                // Resolve remote address.
                Ok(SharedQueueSlot { local, remote, data }) => match arp.query(remote.unwrap().get_address()).await {
                    // Send datagram.
                    Ok(link_addr) => {
                        Self::do_send(
                            rt.clone(),
                            local_ipv4_addr,
                            local_link_addr,
                            link_addr,
                            data,
                            local,
                            remote.unwrap(),
                            offload_checksum,
                        );
                    },
                    // ARP query failed.
                    Err(e) => warn!("Failed to send UDP datagram: {:?}", e),
                },
                // Pop from shared queue failed.
                Err(e) => warn!("Failed to send UDP datagram: {:?}", e),
            }
        }
    }

    /// Opens a UDP socket.
    pub fn do_socket(&mut self, qd: QDesc) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::socket");

        // Lookup for an existing socket associated to this queue descriptor.
        match self.sockets.contains_key(&qd) {
            // Que descriptor not used.
            false => {
                let socket: Option<Ipv4Endpoint> = None;
                self.sockets.insert(qd, socket);
                Ok(())
            },
            // Queue descriptor in use.
            true => return Err(Fail::new(EEXIST, "queue descriptor in use")),
        }
    }

    /// Binds a UDP socket to a local endpoint address.
    pub fn do_bind(&mut self, qd: QDesc, addr: Ipv4Endpoint) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::bind");

        // Local endpoint address in use.
        if self.bound.contains_key(&addr) {
            return Err(Fail::new(EADDRINUSE, "address in use"));
        }

        // Register local endpoint address.
        match self.sockets.get_mut(&qd) {
            Some(s) if s.is_none() => {
                *s = Some(addr);
            },
            _ => return Err(Fail::new(EBADF, "invalid queue descriptor")),
        }

        // Bind endpoint and create a receiver-side shared queue.
        let queue: SharedQueue<SharedQueueSlot<Box<dyn Buffer>>> =
            SharedQueue::<SharedQueueSlot<Box<dyn Buffer>>>::new();
        if self.bound.insert(addr, queue).is_some() {
            return Err(Fail::new(EADDRINUSE, "address in use"));
        }

        Ok(())
    }

    /// Closes a UDP socket.
    pub fn do_close(&mut self, qd: QDesc) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::close");

        // Lookup associated endpoint.
        let socket: Option<Ipv4Endpoint> = match self.sockets.remove(&qd) {
            Some(s) => s,
            None => return Err(Fail::new(EBADF, "invalid queue descriptor")),
        };

        // Remove endpoint binding.
        match socket {
            Some(local) if self.bound.remove(&local).is_some() => Ok(()),
            _ => return Err(Fail::new(EBADF, "invalid queue descriptor")),
        }
    }

    /// Pushes data to a remote UDP peer.
    pub fn do_pushto(&self, qd: QDesc, data: Box<dyn Buffer>, remote: Ipv4Endpoint) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::pushto");

        // Lookup associated endpoint.
        let local: Option<Ipv4Endpoint> = match self.sockets.get(&qd) {
            Some(s) if s.is_some() => *s,
            _ => return Err(Fail::new(EBADF, "invalid queue descriptor")),
        };

        // Fast path: try to send the datagram immediately.
        if let Some(link_addr) = self.arp.try_query(remote.get_address()) {
            Self::do_send(
                self.rt.clone(),
                self.local_ipv4_addr,
                self.local_link_addr,
                link_addr,
                data,
                local,
                remote,
                self.checksum_offload,
            );
        }
        // Slow path: Defer send operation to the async path.
        else {
            self.send_queue.push(SharedQueueSlot {
                local,
                remote: Some(remote),
                data,
            })?
        }

        Ok(())
    }

    /// Pops data from a socket.
    pub fn do_pop(&self, qd: QDesc) -> UdpPopFuture {
        #[cfg(feature = "profiler")]
        timer!("udp::pop");

        // Lookup associated receiver-side shared queue.
        let recv_queue: SharedQueue<SharedQueueSlot<Box<dyn Buffer>>> = match self.sockets.get(&qd) {
            Some(s) if s.is_some() => self.bound.get(&s.unwrap()).unwrap().clone(),
            _ => panic!("invalid queue descriptor"),
        };

        // Issue pop operation.
        UdpPopFuture::new(qd, recv_queue)
    }

    /// Consumes the payload from a buffer.
    pub fn do_receive(&mut self, ipv4_hdr: &Ipv4Header, buf: Box<dyn Buffer>) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::receive");

        // Parse datagram.
        let (hdr, data): (UdpHeader, Box<dyn Buffer>) = UdpHeader::parse(ipv4_hdr, buf, self.checksum_offload)?;
        debug!("UDP received {:?}", hdr);

        let local: Ipv4Endpoint = Ipv4Endpoint::new(ipv4_hdr.get_dest_addr(), hdr.dest_port());
        let remote: Option<Ipv4Endpoint> = hdr.src_port().map(|p| Ipv4Endpoint::new(ipv4_hdr.get_src_addr(), p));

        // Lookup associated receiver-side shared queue.
        let recv_queue: &mut SharedQueue<SharedQueueSlot<Box<dyn Buffer>>> = match self.bound.get_mut(&local) {
            Some(q) => q,
            // TODO: Send ICMPv4 error in this condition.
            None => Err(Fail::new(ENOTCONN, "port not bound"))?,
        };

        // Push data to the receiver-side shared queue. This will cause the
        // associated pool operation to be ready.
        recv_queue
            .push(SharedQueueSlot {
                local: Some(local),
                remote,
                data,
            })
            .unwrap();

        Ok(())
    }

    /// Sends a UDP datagram.
    fn do_send(
        rt: RT,
        local_ipv4_addr: Ipv4Addr,
        local_link_addr: MacAddress,
        remote_link_addr: MacAddress,
        buf: Box<dyn Buffer>,
        local: Option<Ipv4Endpoint>,
        remote: Ipv4Endpoint,
        offload_checksum: bool,
    ) {
        let udp_header: UdpHeader = UdpHeader::new(local.map(|l| l.get_port()), remote.get_port());
        debug!("UDP send {:?}", udp_header);
        let datagram = UdpDatagram::new(
            Ethernet2Header::new(remote_link_addr, local_link_addr, EtherType2::Ipv4),
            Ipv4Header::new(local_ipv4_addr, remote.get_address(), IpProtocol::UDP),
            udp_header,
            buf,
            offload_checksum,
        );
        rt.transmit(datagram);
    }
}
