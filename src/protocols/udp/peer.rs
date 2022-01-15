// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    datagram::{UdpDatagram, UdpHeader},
    listener::Listener,
    operations::PopFuture,
    socket::Socket,
};

use crate::{
    fail::Fail,
    file_table::{File, FileDescriptor, FileTable},
    protocols::{
        arp,
        ethernet2::frame::{EtherType2, Ethernet2Header},
        ipv4,
        ipv4::datagram::{Ipv4Header, Ipv4Protocol2},
    },
    runtime::Runtime,
    scheduler::SchedulerHandle,
};
use futures::{channel::mpsc, stream::StreamExt};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

#[cfg(feature = "profiler")]
use perftools::timer;

//==============================================================================
// Constants & Structures
//==============================================================================

type OutgoingReq<T> = (Option<ipv4::Endpoint>, ipv4::Endpoint, T);
type OutgoingSender<T> = mpsc::UnboundedSender<OutgoingReq<T>>;
type OutgoingReceiver<T> = mpsc::UnboundedReceiver<OutgoingReq<T>>;

///
/// UDP Peer
///
/// # References
///
/// - See https://datatracker.ietf.org/doc/html/rfc768 for details on UDP.
///
struct UdpPeerInner<RT: Runtime> {
    rt: RT,
    arp: arp::Peer<RT>,
    file_table: FileTable,

    sockets: HashMap<FileDescriptor, Socket>,
    bound: HashMap<ipv4::Endpoint, Rc<RefCell<Listener<RT::Buf>>>>,

    outgoing: OutgoingSender<RT::Buf>,
    #[allow(unused)]
    handle: SchedulerHandle,
}

pub struct UdpPeer<RT: Runtime> {
    inner: Rc<RefCell<UdpPeerInner<RT>>>,
}

//==============================================================================
// Associate Functions
//==============================================================================

/// Associate functions for [UdpPeerInner].
impl<RT: Runtime> UdpPeerInner<RT> {
    /// Creates a UDP peer inner.
    fn new(
        rt: RT,
        arp: arp::Peer<RT>,
        file_table: FileTable,
        tx: OutgoingSender<RT::Buf>,
        handle: SchedulerHandle,
    ) -> Self {
        Self {
            rt,
            arp,
            file_table,
            sockets: HashMap::new(),
            bound: HashMap::new(),
            outgoing: tx,
            handle,
        }
    }

    /// Sends a UDP packet.
    fn send_datagram(
        &self,
        buf: RT::Buf,
        local: Option<ipv4::Endpoint>,
        remote: ipv4::Endpoint,
    ) -> Result<(), Fail> {
        // First, try to send the packet immediately. If we can't defer the
        // operation to the async path.
        if let Some(link_addr) = self.arp.try_query(remote.addr) {
            let udp_header = UdpHeader::new(local.map(|l| l.port), remote.port);
            debug!("UDP send {:?}", udp_header);
            let datagram = UdpDatagram::new(
                Ethernet2Header {
                    dst_addr: link_addr,
                    src_addr: self.rt.local_link_addr(),
                    ether_type: EtherType2::Ipv4,
                },
                Ipv4Header::new(self.rt.local_ipv4_addr(), remote.addr, Ipv4Protocol2::Udp),
                udp_header,
                buf,
                self.rt.udp_options().tx_checksum(),
            );
            self.rt.transmit(datagram);
        } else {
            self.outgoing.unbounded_send((local, remote, buf)).unwrap();
        }
        Ok(())
    }
}

/// Associate functions for [UdpPeer].
impl<RT: Runtime> UdpPeer<RT> {
    /// Creates a Udp peer.
    pub fn new(rt: RT, arp: arp::Peer<RT>, file_table: FileTable) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let future = Self::background(rt.clone(), arp.clone(), rx);
        let handle = rt.spawn(future);
        let inner = UdpPeerInner::new(rt, arp, file_table, tx, handle);
        Self {
            inner: Rc::new(RefCell::new(inner)),
        }
    }

    async fn background(rt: RT, arp: arp::Peer<RT>, mut rx: OutgoingReceiver<RT::Buf>) {
        while let Some((local, remote, buf)) = rx.next().await {
            let r: Result<_, Fail> = try {
                let link_addr = arp.query(remote.addr).await?;
                let datagram = UdpDatagram::new(
                    Ethernet2Header {
                        dst_addr: link_addr,
                        src_addr: rt.local_link_addr(),
                        ether_type: EtherType2::Ipv4,
                    },
                    Ipv4Header::new(rt.local_ipv4_addr(), remote.addr, Ipv4Protocol2::Udp),
                    UdpHeader::new(local.map(|l| l.port), remote.port),
                    buf,
                    rt.udp_options().tx_checksum(),
                );
                rt.transmit(datagram);
            };
            if let Err(e) = r {
                warn!("Failed to send UDP message: {:?}", e);
            }
        }
    }

    ///
    /// Dummy accept operation.
    ///
    /// - TODO: we should drop this function because it is meaningless for UDP.
    ///
    pub fn accept(&self) -> Fail {
        Fail::Malformed {
            details: "Operation not supported",
        }
    }

    /// Opens a UDP socket.
    pub fn socket(&self) -> Result<FileDescriptor, Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::socket");

        let mut inner = self.inner.borrow_mut();
        let fd = inner.file_table.alloc(File::UdpSocket);
        let socket = Socket::default();
        if inner.sockets.insert(fd, socket).is_some() {
            return Err(Fail::TooManyOpenedFiles {
                details: "file table overflow",
            });
        }
        Ok(fd)
    }

    /// Binds a socket to an endpoint address.
    pub fn bind(&self, fd: FileDescriptor, addr: ipv4::Endpoint) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::bind");

        let mut inner = self.inner.borrow_mut();
        // Endpoint in use.
        if inner.bound.contains_key(&addr) {
            return Err(Fail::Malformed {
                details: "Port already listening",
            });
        }

        // Update file descriptor with local endpoint.
        match inner.sockets.get_mut(&fd) {
            Some(s) if s.local().is_none() => {
                s.set_local(Some(addr));
            }
            _ => return Err(Fail::BadFileDescriptor {}),
        }

        // Register listener.
        let listener = Listener::default();
        if inner
            .bound
            .insert(addr, Rc::new(RefCell::new(listener)))
            .is_some()
        {
            return Err(Fail::AddressInUse {});
        }

        Ok(())
    }

    ///
    /// Dummy accept operation.
    ///
    /// - TODO: we should drop this function because it is meaningless for UDP.
    ///
    pub fn connect(&self, _fd: FileDescriptor, _addr: ipv4::Endpoint) -> Result<(), Fail> {
        Err(Fail::Malformed {
            details: "Operation not supported",
        })
    }

    /// Closes a socket.
    pub fn close(&self, fd: FileDescriptor) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::close");

        let mut inner = self.inner.borrow_mut();

        let socket = match inner.sockets.remove(&fd) {
            Some(s) => s,
            None => return Err(Fail::BadFileDescriptor {}),
        };

        // Remove endpoint biding.
        if let Some(local) = socket.local() {
            if inner.bound.remove(&local).is_none() {
                return Err(Fail::BadFileDescriptor {});
            }
        }

        // Free file table.
        inner.file_table.free(fd);

        Ok(())
    }

    /// Consumes the payload from a buffer.
    pub fn receive(&self, ipv4_header: &Ipv4Header, buf: RT::Buf) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::receive");

        let mut inner = self.inner.borrow_mut();
        let (hdr, data) = UdpHeader::parse(ipv4_header, buf, inner.rt.udp_options().rx_checksum())?;
        debug!("UDP received {:?}", hdr);
        let local = ipv4::Endpoint::new(ipv4_header.dst_addr, hdr.dest_port());
        let remote = hdr
            .src_port()
            .map(|p| ipv4::Endpoint::new(ipv4_header.src_addr, p));

        // TODO: Send ICMPv4 error in this condition.
        let listener = inner.bound.get_mut(&local).ok_or(Fail::Malformed {
            details: "Port not bound",
        })?;

        // Consume data and wakeup receiver.
        let mut l = listener.borrow_mut();
        l.push_data(remote, data);
        if let Some(w) = l.take_waker() {
            w.wake()
        }

        Ok(())
    }

    /// Pushes data to a socket.
    pub fn push(&self, fd: FileDescriptor, buf: RT::Buf) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::push");

        let inner = self.inner.borrow();
        match inner.sockets.get(&fd) {
            Some(s) if s.local().is_some() && s.remote().is_some() => {
                inner.send_datagram(buf, s.local(), s.remote().unwrap())
            }
            Some(s) if s.local().is_some() => Err(Fail::BadFileDescriptor {}),
            Some(s) if s.remote().is_some() => Err(Fail::BadFileDescriptor {}),
            _ => Err(Fail::Malformed {
                details: "Invalid file descriptor",
            }),
        }
    }

    pub fn pushto(&self, fd: FileDescriptor, buf: RT::Buf, to: ipv4::Endpoint) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("udp::pushto");

        let inner = self.inner.borrow();
        let local = match inner.sockets.get(&fd) {
            Some(s) if s.local().is_some() => s.local(),
            _ => return Err(Fail::BadFileDescriptor {}),
        };
        inner.send_datagram(buf, local, to)
    }

    /// Pops data from a socket.
    pub fn pop(&self, fd: FileDescriptor) -> PopFuture<RT> {
        #[cfg(feature = "profiler")]
        timer!("udp::pop");

        let inner = self.inner.borrow();
        let listener = match inner.sockets.get(&fd) {
            Some(s) if s.local().is_some() => {
                Ok(inner.bound.get(&s.local().unwrap()).unwrap().clone())
            }
            _ => Err(Fail::Malformed {
                details: "Invalid file descriptor",
            }),
        };

        PopFuture::new(fd, listener)
    }
}
