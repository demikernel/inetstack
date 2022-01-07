// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    receiver::Receiver,
    sender::congestion_ctrl,
    sender::Sender,
    sender::{congestion_ctrl::CongestionControlConstructor, UnackedSegment},
};

use crate::{
    collections::watched::WatchFuture,
    collections::watched::WatchedValue,
    fail::Fail,
    protocols::{
        arp,
        ethernet2::{
            frame::{EtherType2, Ethernet2Header},
            MacAddress,
        },
        ipv4,
        ipv4::datagram::{Ipv4Header, Ipv4Protocol2},
        tcp::{
            segment::{TcpHeader, TcpSegment},
            SeqNumber,
        },
    },
    runtime::Runtime,
};
use std::{
    num::Wrapping,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
    time::Instant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Established,
    ActiveClose,
    FinWait1,
    FinWait2,
    FinWait3,
    Closing1,
    Closing2,
    TimeWait1,
    TimeWait2,
    PassiveClose,
    CloseWait1,
    CloseWait2,
    LastAck,
    Closed,
    Reset,
}

/// Transmission control block for representing our TCP connection.
pub struct ControlBlock<RT: Runtime> {
    local: ipv4::Endpoint,
    remote: ipv4::Endpoint,

    rt: Rc<RT>,
    arp: Rc<arp::Peer<RT>>,

    /// The sender end of our connection.
    sender: Sender<RT>,
    /// The receiver end of our connection.
    receiver: Receiver<RT>,

    state: WatchedValue<State>,
}

impl<RT: Runtime> ControlBlock<RT> {
    pub fn new(
        local: ipv4::Endpoint,
        remote: ipv4::Endpoint,
        rt: RT,
        arp: arp::Peer<RT>,
        receiver_seq_no: SeqNumber,
        ack_delay_timeout: Duration,
        receiver_window_size: u32,
        receiver_window_scale: u32,
        sender_seq_no: SeqNumber,
        sender_window_size: u32,
        sender_window_scale: u8,
        sender_mss: usize,
        sender_cc_constructor: CongestionControlConstructor<RT>,
        sender_congestion_control_options: Option<congestion_ctrl::Options>,
    ) -> Self {
        let receiver = Receiver::new(
            receiver_seq_no,
            ack_delay_timeout,
            receiver_window_size,
            receiver_window_scale,
        );
        let sender = Sender::new(
            sender_seq_no,
            sender_window_size,
            sender_window_scale,
            sender_mss,
            sender_cc_constructor,
            sender_congestion_control_options,
        );
        Self {
            local,
            remote,
            rt: Rc::new(rt),
            arp: Rc::new(arp),
            sender: sender,
            receiver: receiver,
            state: WatchedValue::new(State::Established),
        }
    }

    pub fn get_state(&self) -> (State, WatchFuture<State>) {
        self.state.watch()
    }

    pub fn set_state(&self, new_value: State) {
        self.state.set(new_value)
    }

    pub fn get_local(&self) -> ipv4::Endpoint {
        self.local
    }

    pub fn get_remote(&self) -> ipv4::Endpoint {
        self.remote
    }

    pub fn rt(&self) -> Rc<RT> {
        self.rt.clone()
    }

    pub fn arp(&self) -> Rc<arp::Peer<RT>> {
        self.arp.clone()
    }

    pub fn send(&self, buf: RT::Buf) -> Result<(), Fail> {
        if self.state.get() != State::Established {
            return Err(Fail::Ignored {
                details: "Sender closed",
            });
        }

        self.sender.send(buf, self)
    }

    pub fn congestion_ctrl_watch_retransmit_now_flag(&self) -> (bool, WatchFuture<bool>) {
        self.sender.congestion_ctrl_watch_retransmit_now_flag()
    }

    pub fn congestion_ctrl_on_fast_retransmit(&self) {
        self.sender.congestion_ctrl_on_fast_retransmit()
    }

    pub fn congestion_ctrl_on_rto(&self, base_seq_no: Wrapping<u32>) {
        self.sender.congestion_ctrl_on_rto(base_seq_no)
    }

    pub fn congestion_ctrl_on_send(&self, rto: Duration, num_sent_bytes: u32) {
        self.sender.congestion_ctrl_on_send(rto, num_sent_bytes)
    }

    pub fn congestion_ctrl_on_cwnd_check_before_send(&self) {
        self.sender.congestion_ctrl_on_cwnd_check_before_send()
    }

    pub fn congestion_ctrl_watch_cwnd(&self) -> (u32, WatchFuture<u32>) {
        self.sender.congestion_ctrl_watch_cwnd()
    }

    pub fn congestion_ctrl_watch_limited_transmit_cwnd_increase(&self) -> (u32, WatchFuture<u32>) {
        self.sender
            .congestion_ctrl_watch_limited_transmit_cwnd_increase()
    }

    pub fn get_mss(&self) -> usize {
        self.sender.get_mss()
    }

    pub fn get_window_size(&self) -> (u32, WatchFuture<u32>) {
        self.sender.get_window_size()
    }

    pub fn get_base_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.sender.get_base_seq_no()
    }

    pub fn get_unsent_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.sender.get_unsent_seq_no()
    }

    pub fn get_sent_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.sender.get_sent_seq_no()
    }

    pub fn modify_sent_seq_no(&self, f: impl FnOnce(Wrapping<u32>) -> Wrapping<u32>) {
        self.sender.modify_sent_seq_no(f)
    }

    pub fn get_last_ack_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.receiver.get_ack_seq_no()
    }

    pub fn get_last_recv_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.receiver.get_recv_seq_no()
    }

    pub fn get_ack_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.receiver.get_ack_deadline()
    }

    pub fn get_retransmit_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.sender.get_retransmit_deadline()
    }

    pub fn set_retransmit_deadline(&self, when: Option<Instant>) {
        self.sender.set_retransmit_deadline(when);
    }

    pub fn pop_unacked_segment(&self) -> Option<UnackedSegment<RT>> {
        self.sender.pop_unacked_segment()
    }

    pub fn push_unacked_segment(&self, segment: UnackedSegment<RT>) {
        self.sender.push_unacked_segment(segment)
    }

    pub fn rto_estimate(&self) -> Duration {
        self.sender.rto_estimate()
    }

    pub fn rto_record_failure(&self) {
        self.sender.rto_record_failure()
    }

    pub fn unsent_top_size(&self) -> Option<usize> {
        self.sender.top_size_unsent()
    }

    pub fn pop_unsent_segment(&self, max_bytes: usize) -> Option<RT::Buf> {
        self.sender.pop_unsent(max_bytes)
    }

    pub fn pop_one_unsent_byte(&self) -> Option<RT::Buf> {
        self.sender.pop_one_unsent_byte()
    }

    pub fn poll_recv(&self, ctx: &mut Context) -> Poll<Result<RT::Buf, Fail>> {
        if self.state.get() != State::Established {
            return Poll::Ready(Err(Fail::ResourceNotFound {
                details: "Receiver closed",
            }));
        }
        self.receiver.poll_recv(ctx)
    }

    pub fn receive(&self, header: &TcpHeader, data: RT::Buf) {
        debug!(
            "{:?} Connection Receiving {} bytes + {:?}",
            self.state.get(),
            data.len(),
            header
        );
        let now = self.rt.now();
        if header.syn {
            warn!("Ignoring duplicate SYN on established connection");
        }
        if header.rst {
            self.state.set(State::Reset);
        }
        if header.fin && header.ack {
            match self.state.get() {
                State::FinWait1 => self.state.set(State::TimeWait1),
                s => panic!("bad peer state {:?}", s),
            }
        } else {
            if header.fin {
                match self.state.get() {
                    State::FinWait1 => self.state.set(State::Closing1),
                    State::FinWait2 => self.state.set(State::FinWait3),
                    State::Established => self.state.set(State::PassiveClose),
                    s => panic!("bad peer state {:?}", s),
                }
            }
            if header.ack {
                match self.state.get() {
                    State::FinWait1 => self.state.set(State::FinWait2),
                    State::Closing2 => self.state.set(State::TimeWait2),
                    State::Established => {
                        if let Err(e) = self.sender.remote_ack(header.ack_num, now) {
                            warn!("Ignoring remote ack for {:?}: {:?}", header, e);
                        }
                    }
                    State::LastAck => self.state.set(State::Closed),
                    s => panic!("bad peer state {:?}", s),
                }
            }
        }
        if self.state.get() == State::Established {
            if let Err(e) = self.sender.update_remote_window(header.window_size as u16) {
                warn!("Invalid window size update for {:?}: {:?}", header, e);
            }
        }
        if !data.is_empty() {
            if self.state.get() != State::Established {
                warn!("Receiver closed");
            }
            if let Err(e) = self.receiver.receive_data(header.seq_num, data, now) {
                warn!("Ignoring remote data for {:?}: {:?}", header, e);
            }
        }
    }

    pub fn close(&self) -> Result<(), Fail> {
        match self.state.get() {
            State::Established => self.state.set(State::ActiveClose),
            State::CloseWait1 => self.state.set(State::CloseWait2),
            s => panic!("bad state {:?}", s),
        }

        Ok(())
    }

    /// Fetch a TCP header filling out various values based on our current state.
    pub fn tcp_header(&self) -> TcpHeader {
        let mut header = TcpHeader::new(self.local.port, self.remote.port);
        header.window_size = self.receiver.hdr_window_size();

        // Check if we have acknowledged all bytes that we have received. If not, piggy back an ACK
        // on this message.
        if self.state.get() != State::CloseWait2 {
            if let Some(ack_seq_no) = self.receiver.current_ack() {
                header.ack_num = ack_seq_no;
                header.ack = true;
            }
        }
        header
    }

    /// Transmit this message to our connected peer.
    pub fn emit(&self, header: TcpHeader, data: RT::Buf, remote_link_addr: MacAddress) {
        if header.ack {
            let (recv_seq_no, _) = self.receiver.get_recv_seq_no();
            if self.state.get() == State::PassiveClose || self.state.get() == State::FinWait3 {
                assert_eq!(header.ack_num, recv_seq_no + Wrapping(1));
            } else {
                assert_eq!(header.ack_num, recv_seq_no);
            }
            self.receiver.set_ack_deadline(None);
            self.receiver.set_ack_seq_no(header.ack_num);
        }

        debug!("Sending {} bytes + {:?}", data.len(), header);
        let segment = TcpSegment {
            ethernet2_hdr: Ethernet2Header {
                dst_addr: remote_link_addr,
                src_addr: self.rt.local_link_addr(),
                ether_type: EtherType2::Ipv4,
            },
            ipv4_hdr: Ipv4Header::new(self.local.addr, self.remote.addr, Ipv4Protocol2::Tcp),
            tcp_hdr: header,
            data,
            tx_checksum_offload: self.rt.tcp_options().tx_checksum_offload(),
        };
        self.rt.transmit(segment);
    }

    pub fn remote_mss(&self) -> usize {
        self.sender.remote_mss()
    }

    pub fn current_rto(&self) -> Duration {
        self.sender.current_rto()
    }
}
