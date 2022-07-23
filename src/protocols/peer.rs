// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::protocols::{
    arp::ArpPeer,
    icmpv4::Icmpv4Peer,
    ip::IpProtocol,
    ipv4::Ipv4Header,
    tcp::TcpPeer,
    udp::UdpPeer,
};
use ::libc::ENOTCONN;
use ::runtime::{
    fail::Fail,
    memory::Buffer,
    network::{
        types::MacAddress,
        NetworkRuntime,
    },
    scheduler::Scheduler,
    timer::TimerRc,
};
use ::std::{
    future::Future,
    net::Ipv4Addr,
    time::Duration,
};

#[cfg(test)]
use ::runtime::QDesc;

pub struct Peer<RT: NetworkRuntime + Clone + 'static> {
    rt: RT,
    icmpv4: Icmpv4Peer<RT>,
    pub tcp: TcpPeer<RT>,
    pub udp: UdpPeer<RT>,
}

impl<RT: NetworkRuntime + Clone + 'static> Peer<RT> {
    pub fn new(
        rt: RT,
        scheduler: Scheduler,
        clock: TimerRc,
        arp: ArpPeer<RT>,
        rng_seed: [u8; 32],
    ) -> Result<Peer<RT>, Fail> {
        let local_link_addr: MacAddress = rt.local_link_addr();
        let local_ipv4_addr: Ipv4Addr = rt.local_ipv4_addr();
        let udp_offload_checksum: bool = rt.udp_options().get_tx_checksum_offload();
        let udp: UdpPeer<RT> = UdpPeer::new(
            rt.clone(),
            scheduler.clone(),
            rng_seed,
            local_link_addr,
            local_ipv4_addr,
            udp_offload_checksum,
            arp.clone(),
        )?;
        let icmpv4: Icmpv4Peer<RT> =
            Icmpv4Peer::new(rt.clone(), scheduler.clone(), clock.clone(), arp.clone(), rng_seed)?;
        let tcp: TcpPeer<RT> = TcpPeer::new(rt.clone(), scheduler.clone(), clock.clone(), arp, rng_seed)?;

        Ok(Peer { rt, icmpv4, tcp, udp })
    }

    pub fn receive(&mut self, buf: Buffer) -> Result<(), Fail> {
        let (header, payload) = Ipv4Header::parse(buf)?;
        debug!("Ipv4 received {:?}", header);
        if header.get_dest_addr() != self.rt.local_ipv4_addr() && !header.get_dest_addr().is_broadcast() {
            return Err(Fail::new(ENOTCONN, "invalid destination address"));
        }
        match header.get_protocol() {
            IpProtocol::ICMPv4 => self.icmpv4.receive(&header, payload),
            IpProtocol::TCP => self.tcp.receive(&header, payload),
            IpProtocol::UDP => self.udp.do_receive(&header, payload),
        }
    }

    pub fn ping(
        &mut self,
        dest_ipv4_addr: Ipv4Addr,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<Duration, Fail>> {
        self.icmpv4.ping(dest_ipv4_addr, timeout)
    }
}

#[cfg(test)]
impl<RT: NetworkRuntime + Clone + 'static> Peer<RT> {
    pub fn tcp_mss(&self, fd: QDesc) -> Result<usize, Fail> {
        self.tcp.remote_mss(fd)
    }

    pub fn tcp_rto(&self, fd: QDesc) -> Result<Duration, Fail> {
        self.tcp.current_rto(fd)
    }
}
