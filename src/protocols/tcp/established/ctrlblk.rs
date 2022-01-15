// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    sender::congestion_ctrl,
    sender::Sender,
    sender::{congestion_ctrl::CongestionControlConstructor, UnackedSegment},
};

use crate::{
    collections::watched::{WatchFuture, WatchedValue},
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
    cell::RefCell,
    collections::VecDeque,
    convert::TryInto,
    rc::Rc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

// ToDo: Review this value (and its purpose).  It (2048 segments) of 8 KB jumbo packets would limit the unread data to
// just 16 MB.  If we don't want to lie, that is also about the max window size we should ever advertise.  Whereas TCP
// with the window scale option allows for window sizes of up to 1 GB.  This value appears to exist more because of the
// mechanism used to manage the receive queue (a VecDeque) than anything else.
const RECV_QUEUE_SZ: usize = 2048;

// ToDo: Review this value (and its purpose).  It (16 segments) seems awfully small (would make fast retransmit less
// useful), and this mechanism isn't the best way to protect ourselves against deliberate out-of-order segment attacks.
// Ideally, we'd limit out-of-order data to that which (along with the unread data) will fit in the receive window.
const MAX_OUT_OF_ORDER: usize = 16;

// ToDo: Review this.  The TCP Specification doesn't have states called ActiveClose, FinWait3, Closing2, TimeWait2,
// PassiveClose, CloseWait2 or Reset.  And it has states Listen, SynReceived, and SynSent, which aren't listed here.
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

struct ReceiveQueue<RT: Runtime> {
    // ToDo: This diagram appears to be wrong.  It doesn't appear to reflect how the code is currently written, and it
    // certainly doesn't reflect how the code should be written.  See RFC 793, Figure 5 for what this should look like.
    // Instead of base_seq_no, ack_seq_no, and recv_seq_no, we should just be tracking RCV.NXT and how much unread data
    // there is in the receive queue (the latter is used to calculate the receive window to advertise).
    //
    //
    //                     |-----------------recv_window-------------------|
    //                base_seq_no             ack_seq_no             recv_seq_no
    //                     v                       v                       v
    // ... ----------------|-----------------------|-----------------------| (unavailable)
    //         received           acknowledged           unacknowledged
    //
    // NB: We can have `ack_seq_no < base_seq_no` when the application fully drains the receive
    // buffer before we've sent a pure ACK or transmitted some data on which we could piggyback
    // an ACK. The sender, however, will still be computing the receive window relative to the
    // the old `ack_seq_no` until we send them an ACK (see the diagram in sender.rs).
    //

    // ToDo: Figure out what this "base_seq_no" is supposed to reflect.
    pub base_seq_no: WatchedValue<SeqNumber>,

    // Running counter of ack sequence number we have sent to peer.
    // ToDo: In RFC 793 terms, this appears to be RCV.NXT.  Probably should rename to rcv_nxt or something.
    pub ack_seq_no: WatchedValue<SeqNumber>,

    // Our sequence number based on how much data we have sent.
    // ToDo: Fix above comment, as it is clearly wrong.  It has nothing to do with how much data we have sent.  From
    // the above ASCII-art diagram, this sequence number is RCV.NXT + RCV.WND?  However, the receive_data function
    // below behaves as if this sequence number *is* RCV.NXT.
    pub recv_seq_no: WatchedValue<SeqNumber>,

    // Receive queue.  Contains in-order received (and acknowledged) data ready for the application to read.
    recv_queue: RefCell<VecDeque<RT::Buf>>,
}

impl<RT: Runtime> ReceiveQueue<RT> {
    pub fn new(base_seq_no: SeqNumber, ack_seq_no: SeqNumber, recv_seq_no: SeqNumber) -> Self {
        Self {
            base_seq_no: WatchedValue::new(base_seq_no),
            ack_seq_no: WatchedValue::new(ack_seq_no),
            recv_seq_no: WatchedValue::new(recv_seq_no),
            recv_queue: RefCell::new(VecDeque::with_capacity(RECV_QUEUE_SZ)),
        }
    }

    pub fn pop(&self) -> Option<RT::Buf> {
        let buf: RT::Buf = self.recv_queue.borrow_mut().pop_front()?;
        self.base_seq_no.modify(|b| b + SeqNumber::from(buf.len() as u32));

        Some(buf)
    }

    pub fn push(&self, buf: RT::Buf) {
        let buf_len: u32 = buf.len() as u32;
        self.recv_queue.borrow_mut().push_back(buf);
        self.recv_seq_no.modify(|r| r + SeqNumber::from(buf_len as u32));
    }

    // ToDo: This appears to add up all the bytes ready for reading in the recv_queue, and is called each time we get a
    // new segment.  Seems like it would be more efficient to keep a running count of the bytes in the queue that we
    // add/subtract from as we add/remove segments from the queue.
    pub fn size(&self) -> usize {
        self.recv_queue
            .borrow()
            .iter()
            .map(|b| b.len())
            .sum::<usize>()
    }
}

/// Transmission control block for representing our TCP connection.
pub struct ControlBlock<RT: Runtime> {
    local: ipv4::Endpoint,
    remote: ipv4::Endpoint,

    rt: Rc<RT>,
    arp: Rc<arp::Peer<RT>>,

    /// The sender end of our connection.
    sender: Sender<RT>,

    state: WatchedValue<State>,

    ack_delay_timeout: Duration,

    ack_deadline: WatchedValue<Option<Instant>>,

    max_window_size: u32,
    window_scale: u32,

    waker: RefCell<Option<Waker>>,
    out_of_order: RefCell<VecDeque<(SeqNumber, RT::Buf)>>,

    receive_queue: ReceiveQueue<RT>,
}

//==============================================================================

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
            state: WatchedValue::new(State::Established),
            ack_delay_timeout,
            ack_deadline: WatchedValue::new(None),
            max_window_size: receiver_window_size,
            window_scale: receiver_window_scale,
            waker: RefCell::new(None),
            out_of_order: RefCell::new(VecDeque::new()),
            receive_queue: ReceiveQueue::new(receiver_seq_no, receiver_seq_no, receiver_seq_no),
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

    pub fn congestion_ctrl_on_rto(&self, base_seq_no: SeqNumber) {
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

    pub fn get_base_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.sender.get_base_seq_no()
    }

    pub fn get_unsent_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.sender.get_unsent_seq_no()
    }

    pub fn get_sent_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.sender.get_sent_seq_no()
    }

    pub fn modify_sent_seq_no(&self, f: impl FnOnce(SeqNumber) -> SeqNumber) {
        self.sender.modify_sent_seq_no(f)
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
                // ToDo: Review this warning.  TCP connections in FIN_WAIT_1 and FIN_WAIT_2 can still receive data.
                warn!("Receiver closed");
            }
            if let Err(e) = self.receive_data(header.seq_num, data, now) {
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
        header.window_size = self.hdr_window_size();

        // Check if we have acknowledged all bytes that we have received. If not, piggy back an ACK
        // on this message.
        // ToDo: This is a bug (or two).  Except for an active open SYN where we don't yet have a remote sequence
        // number to acknowledge, we should *always* ACK.
        if self.state.get() != State::CloseWait2 {
            if let Some(ack_seq_no) = self.current_ack() {
                header.ack_num = ack_seq_no;
                header.ack = true;
            }
        }
        header
    }

    /// Transmit this message to our connected peer.
    pub fn emit(&self, header: TcpHeader, data: RT::Buf, remote_link_addr: MacAddress) {
        if header.ack {
            let (recv_seq_no, _) = self.get_recv_seq_no();
            if self.state.get() == State::PassiveClose || self.state.get() == State::FinWait3 {
                assert_eq!(header.ack_num, recv_seq_no + SeqNumber::from(1));
            } else {
                assert_eq!(header.ack_num, recv_seq_no);
            }
            self.set_ack_deadline(None);
            self.set_ack_seq_no(header.ack_num);
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

    pub fn rto_current(&self) -> Duration {
        self.sender.current_rto()
    }

    pub fn get_ack_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        let (seq_no, fut) = self.receive_queue.ack_seq_no.watch();
        (seq_no, fut)
    }

    pub fn set_ack_seq_no(&self, new_value: SeqNumber) {
        self.receive_queue.ack_seq_no.set(new_value)
    }

    pub fn get_recv_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.receive_queue.recv_seq_no.watch()
    }

    pub fn get_ack_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.ack_deadline.watch()
    }

    pub fn set_ack_deadline(&self, when: Option<Instant>) {
        self.ack_deadline.set(when);
    }

    pub fn hdr_window_size(&self) -> u16 {
        let bytes_outstanding: u32 = (self.receive_queue.recv_seq_no.get() - self.receive_queue.base_seq_no.get()).into();
        let window_size = self.max_window_size - bytes_outstanding;
        let hdr_window_size = (window_size >> self.window_scale)
            .try_into()
            .expect("Window size overflow");
        debug!(
            "Sending window size update -> {} (hdr {}, scale {})",
            (hdr_window_size as u32) << self.window_scale,
            hdr_window_size,
            self.window_scale
        );
        hdr_window_size
    }

    /// Returns the ack sequence number to use for the next packet based on all the bytes we have
    /// received. This ack sequence number will be piggy backed on the next packet send.
    /// If all received bytes have been acknowledged returns None.
    /// ToDo: Again, we should *always* ACK.  So this should always return the current acknowledgement sequence number.
    pub fn current_ack(&self) -> Option<SeqNumber> {
        let ack_seq_no = self.receive_queue.ack_seq_no.get();
        let recv_seq_no = self.receive_queue.recv_seq_no.get();

        // It is okay if ack_seq_no is greater than the seq number. This can happen when we have
        // ACKed a FIN so our ACK number is +1 greater than our seq number.
        // ToDo: The above comment is confusing, ambiguous, and likely also wrong.  FINs consume sequence number space,
        // so we should be including them in our record keeping of the sequence number space received from our peer.
        // Update: There should only be one value involved/returned here, the one equivalent to RCV.NXT.
        if ack_seq_no == recv_seq_no {
            None
        } else {
            Some(recv_seq_no)
        }
    }

    pub fn poll_recv(&self, ctx: &mut Context) -> Poll<Result<RT::Buf, Fail>> {
        if self.receive_queue.base_seq_no.get() == self.receive_queue.recv_seq_no.get() {
            *self.waker.borrow_mut() = Some(ctx.waker().clone());
            return Poll::Pending;
        }

        let segment = self
            .receive_queue
            .pop()
            .expect("recv_seq > base_seq without data in queue?");

        Poll::Ready(Ok(segment))
    }

    // ToDo: Improve following comment:
    // This routine appears to take an incoming TCP segment and either add it to the receiver's queue of data that is
    // ready to be read by the user (if the segment contains in-order data) or add it to the proper position in the
    // receiver's store of out-of-order data.  Also, in the in-order case, it updates our receiver's sequence number
    // corresponding to the minumum number allowed for new reception (RCV.NXT in RFC 793 terms).
    //
    pub fn receive_data(&self, seq_no: SeqNumber, buf: RT::Buf, now: Instant) -> Result<(), Fail> {
        let recv_seq_no = self.receive_queue.recv_seq_no.get();
 
        if seq_no > recv_seq_no {
            // This new segment comes after what we're expecting (i.e. the new segment arrived out-of-order).
            let mut out_of_order = self.out_of_order.borrow_mut();

            // Check if the new data segment's starting sequence number is already in the out-of-order store.
            // ToDo: We should check if any part of the new segment contains new data, and not just the start.
            for stored_segment in out_of_order.iter() {
                if stored_segment.0 == seq_no {
                    // Drop this segment as a duplicate.
                    // ToDo: We should ACK when we drop a segment.
                    return Err(Fail::Ignored {
                        details: "Out of order segment (duplicate)",
                    });
                }
            }

            // Before adding more, if the out-of-order store contains too many entries, delete the later entries.
            while out_of_order.len() > MAX_OUT_OF_ORDER {
                out_of_order.pop_back();
            }

            // Add the new segment to the out-of-order store (the store is sorted by starting sequence number).
            let mut insert_index = out_of_order.len();
            for index in 0..out_of_order.len() {
                if seq_no > out_of_order[index].0 {
                    insert_index = index;
                    break;
                }
            }
            if insert_index < out_of_order.len() {
                out_of_order[insert_index] = (seq_no, buf);
            } else {
                out_of_order.push_back((seq_no, buf));
            }

            // ToDo: There is a bug here.  We should send an ACK when we drop a segment.
            return Err(Fail::Ignored {
                details: "Out of order segment (reordered)",
            });
        }

        // Check if we've already received this data (i.e. new segment contains duplicate data).
        // ToDo: There is a bug here.  The new segment could contain both old *and* new data.  Current code throws it
        // all away.  We need to check if any part of the new segment falls within our receive window.
        if seq_no < recv_seq_no {
            // ToDo: There is a bug here.  We should send an ACK if we drop the segment.
            return Err(Fail::Ignored {
                details: "Out of order segment (duplicate)",
            });
        }

        // If we get here, the new segment begins with the sequence number we're expecting.
        // ToDo: Since this is the "good" case, we should have a fast-path check for it first above, instead of falling
        // through to it (performance improvement).

        let unread_bytes: usize = self.receive_queue.size();

        // This appears to drop segments if their total contents would exceed the receive window.
        // ToDo: There is a bug here.  The segment could also contain some data that fits within the window.  We should
        // still accept the data that fits within the window.
        // ToDo: We should restructure this to convert usize things to known (fixed) sizes, not the other way around.
        if unread_bytes + buf.len() > self.max_window_size as usize {
            // ToDo: There is a bug here.  We should send an ACK if we drop the segment.
            return Err(Fail::Ignored {
                details: "Full receive window",
            });
        }

        // Push the new segment data onto the end of the receive queue.
        let mut recv_seq_no = recv_seq_no + SeqNumber::from(buf.len() as u32);
        self.receive_queue.push(buf);

        // Okay, we've successfully received some new data.  Check if any of the formerly out-of-order data waiting in
        // the out-of-order queue is now in-order.  If so, we can move it to the receive queue.
        let mut out_of_order = self.out_of_order.borrow_mut();
        while !out_of_order.is_empty() {
            if let Some(stored_entry) = out_of_order.front() {
                if stored_entry.0 == recv_seq_no {
                    // Move this entry's buffer from the out-of-order store to the receive queue.
                    // This data is now considered to be "received" by TCP, and included in our RCV.NXT calculation.
                    info!("Recovering out-of-order packet at {}", recv_seq_no);
                    if let Some(temp) = out_of_order.pop_front() {
                        recv_seq_no = recv_seq_no + SeqNumber::from(temp.1.len() as u32);
                        self.receive_queue.push(temp.1);
                    }
                } else {
                    // Since our out-of-order list is sorted, we can stop when the next segment is not in sequence.
                    break;
                }
            }
        }

        // ToDo: Review recent change to update control block copy of recv_seq_no upon each push to the receive_queue.
        // When receiving a retransmitted segment that fills a "hole" in the receive space, thus allowing a number
        // (potentially large number) of out-of-order segments to be added, we'll be modifying the TCB copy of the
        // recv_seq_no many times.  Since this potentially wakes a waker, we might want to wait until we've added all
        // the segments before we update the value.
        // Anyhow that recent change removes the need for the following two lines:
            // Update our receive sequence number (i.e. RCV_NXT) appropriately.
            // self.recv_seq_no.set(recv_seq_no);

        // This appears to be checking if something is waiting on this Receiver, and if so, wakes that thing up.
        // ToDo: Verify that this is the right place and time to do this.
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake()
        }

        // TODO: How do we handle when the other side is in PERSIST state here?
        // ToDo: Fix above comment - there is no such thing as a PERSIST state in TCP.  Presumably, this comment means
        // to ask "how do we handle the situation where the other side is sending us zero window probes because it has
        // data to send and no open window to send into?".  The answer is: we should ACK zero-window probes.

        // Schedule an ACK for this receive (if one isn't already).
        // ToDo: Another bug.  If the delayed ACK timer is already running, we should cancel it and ACK immediately.
        if self.ack_deadline.get().is_none() {
            self.ack_deadline.set(Some(now + self.ack_delay_timeout));
        }

        Ok(())
    }
}
