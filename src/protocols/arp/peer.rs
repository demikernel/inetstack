// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    cache::ArpCache,
    packet::{
        ArpHeader,
        ArpMessage,
        ArpOperation,
    },
};
use crate::{
    futures::{
        FutureOperation,
        UtilityMethods,
    },
    protocols::ethernet2::{
        EtherType2,
        Ethernet2Header,
    },
};
use ::futures::{
    channel::oneshot::{
        channel,
        Receiver,
        Sender,
    },
    FutureExt,
};
use ::libc::{
    EBADMSG,
    ETIMEDOUT,
};
use ::runtime::{
    fail::Fail,
    memory::Buffer,
    network::{
        config::ArpConfig,
        types::MacAddress,
        NetworkRuntime,
    },
    scheduler::{
        Scheduler,
        SchedulerHandle,
    },
    timer::TimerRc,
};
use ::std::{
    cell::RefCell,
    collections::HashMap,
    future::Future,
    net::Ipv4Addr,
    rc::Rc,
    time::Duration,
};

//==============================================================================
// Structures
//==============================================================================

///
/// Arp Peer
/// - TODO: Allow multiple waiters for the same address
#[derive(Clone)]
pub struct ArpPeer<RT: NetworkRuntime> {
    rt: RT,
    clock: TimerRc,
    cache: Rc<RefCell<ArpCache>>,
    waiters: Rc<RefCell<HashMap<Ipv4Addr, Sender<MacAddress>>>>,
    options: ArpConfig,

    /// The background co-routine cleans up the ARP cache from time to time.
    /// We annotate it as unused because the compiler believes that it is never called which is not the case.
    #[allow(unused)]
    background: Rc<SchedulerHandle>,
}

//==============================================================================
// Associate Functions
//==============================================================================

impl<RT: NetworkRuntime + Clone + 'static> ArpPeer<RT> {
    pub fn new(rt: RT, scheduler: Scheduler, clock: TimerRc, options: ArpConfig) -> Result<ArpPeer<RT>, Fail> {
        let cache = Rc::new(RefCell::new(ArpCache::new(
            clock.clone(),
            Some(options.get_cache_ttl()),
            Some(options.get_initial_values()),
            options.get_disable_arp(),
        )));

        let future = Self::background(clock.clone(), cache.clone());
        let handle: SchedulerHandle = match scheduler.insert(FutureOperation::Background::<RT>(future.boxed_local())) {
            Some(handle) => handle,
            None => {
                return Err(Fail::new(
                    libc::EAGAIN,
                    "failed to schedule background co-routine for ARP module",
                ))
            },
        };
        let peer = ArpPeer {
            rt,
            clock,
            cache,
            waiters: Rc::new(RefCell::new(HashMap::default())),
            options,
            background: Rc::new(handle),
        };

        Ok(peer)
    }

    /// Drops a waiter for a target IP address.
    fn do_drop(&mut self, ipv4_addr: Ipv4Addr) {
        self.waiters.borrow_mut().remove(&ipv4_addr);
    }

    fn do_insert(&mut self, ipv4_addr: Ipv4Addr, link_addr: MacAddress) -> Option<MacAddress> {
        if let Some(sender) = self.waiters.borrow_mut().remove(&ipv4_addr) {
            let _ = sender.send(link_addr);
        }
        self.cache.borrow_mut().insert(ipv4_addr, link_addr)
    }

    fn do_wait_link_addr(&mut self, ipv4_addr: Ipv4Addr) -> impl Future<Output = MacAddress> {
        let (tx, rx): (Sender<MacAddress>, Receiver<MacAddress>) = channel();
        if let Some(&link_addr) = self.cache.borrow().get(ipv4_addr) {
            let _ = tx.send(link_addr);
        } else {
            assert!(
                self.waiters.borrow_mut().insert(ipv4_addr, tx).is_none(),
                "Duplicate waiter for {:?}",
                ipv4_addr
            );
        }
        rx.map(|r| r.expect("Dropped waiter?"))
    }

    /// Background task that cleans up the ARP cache from time to time.
    async fn background(clock: TimerRc, cache: Rc<RefCell<ArpCache>>) {
        loop {
            let current_time = clock.now();
            {
                let mut cache = cache.borrow_mut();
                cache.advance_clock(current_time);
                // TODO: re-enable eviction once TCP/IP stack is fully functional.
                // cache.clear();
            }
            clock.wait(clock.clone(), Duration::from_secs(1)).await;
        }
    }

    pub fn receive(&mut self, buf: Buffer) -> Result<(), Fail> {
        // from RFC 826:
        // > ?Do I have the hardware type in ar$hrd?
        // > [optionally check the hardware length ar$hln]
        // > ?Do I speak the protocol in ar$pro?
        // > [optionally check the protocol length ar$pln]
        let header = ArpHeader::parse(buf)?;
        debug!("Received {:?}", header);

        // from RFC 826:
        // > Merge_flag := false
        // > If the pair <protocol type, sender protocol address> is
        // > already in my translation table, update the sender
        // > hardware address field of the entry with the new
        // > information in the packet and set Merge_flag to true.
        let merge_flag = {
            if self.cache.borrow().get(header.get_sender_protocol_addr()).is_some() {
                self.do_insert(header.get_sender_protocol_addr(), header.get_sender_hardware_addr());
                true
            } else {
                false
            }
        };
        // from RFC 826: ?Am I the target protocol address?
        if header.get_destination_protocol_addr() != self.rt.local_ipv4_addr() {
            if merge_flag {
                // we did do something.
                return Ok(());
            } else {
                // we didn't do anything.
                return Err(Fail::new(EBADMSG, "unrecognized IP address"));
            }
        }
        // from RFC 826:
        // > If Merge_flag is false, add the triplet <protocol type,
        // > sender protocol address, sender hardware address> to
        // > the translation table.
        if !merge_flag {
            self.do_insert(header.get_sender_protocol_addr(), header.get_sender_hardware_addr());
        }

        match header.get_operation() {
            ArpOperation::Request => {
                // from RFC 826:
                // > Swap hardware and protocol fields, putting the local
                // > hardware and protocol addresses in the sender fields.
                let reply = ArpMessage::new(
                    Ethernet2Header::new(
                        header.get_sender_hardware_addr(),
                        self.rt.local_link_addr(),
                        EtherType2::Arp,
                    ),
                    ArpHeader::new(
                        ArpOperation::Reply,
                        self.rt.local_link_addr(),
                        self.rt.local_ipv4_addr(),
                        header.get_sender_hardware_addr(),
                        header.get_sender_protocol_addr(),
                    ),
                );
                debug!("Responding {:?}", reply);
                self.rt.transmit(reply);
                Ok(())
            },
            ArpOperation::Reply => {
                debug!(
                    "reply from `{}/{}`",
                    header.get_sender_protocol_addr(),
                    header.get_sender_hardware_addr()
                );
                self.cache
                    .borrow_mut()
                    .insert(header.get_sender_protocol_addr(), header.get_sender_hardware_addr());
                Ok(())
            },
        }
    }

    pub fn try_query(&self, ipv4_addr: Ipv4Addr) -> Option<MacAddress> {
        self.cache.borrow().get(ipv4_addr).cloned()
    }

    pub fn query(&self, ipv4_addr: Ipv4Addr) -> impl Future<Output = Result<MacAddress, Fail>> {
        let rt = self.rt.clone();
        let mut arp = self.clone();
        let cache = self.cache.clone();
        let arp_options = self.options.clone();
        let clock: TimerRc = self.clock.clone();
        async move {
            if let Some(&link_addr) = cache.borrow().get(ipv4_addr) {
                return Ok(link_addr);
            }
            let msg = ArpMessage::new(
                Ethernet2Header::new(MacAddress::broadcast(), rt.local_link_addr(), EtherType2::Arp),
                ArpHeader::new(
                    ArpOperation::Request,
                    rt.local_link_addr(),
                    rt.local_ipv4_addr(),
                    MacAddress::broadcast(),
                    ipv4_addr,
                ),
            );
            let mut arp_response = arp.do_wait_link_addr(ipv4_addr).fuse();

            // from TCP/IP illustrated, chapter 4:
            // > The frequency of the ARP request is very close to one per
            // > second, the maximum suggested by [RFC1122].
            let result = {
                for i in 0..arp_options.get_retry_count() + 1 {
                    rt.transmit(msg.clone());
                    let timer = clock.wait(clock.clone(), arp_options.get_request_timeout());

                    match arp_response.with_timeout(timer).await {
                        Ok(link_addr) => {
                            debug!("ARP result available ({})", link_addr);
                            return Ok(link_addr);
                        },
                        Err(_) => {
                            warn!("ARP request timeout; attempt {}.", i + 1);
                        },
                    }
                }
                Err(Fail::new(ETIMEDOUT, "ARP query timeout"))
            };

            arp.do_drop(ipv4_addr);

            result
        }
    }

    #[cfg(test)]
    pub fn export_cache(&self) -> HashMap<Ipv4Addr, MacAddress> {
        self.cache.borrow().export()
    }
}
