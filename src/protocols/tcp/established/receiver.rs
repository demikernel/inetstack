// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    collections::watched::{WatchFuture, WatchedValue},
    fail::Fail,
    protocols::tcp::SeqNumber,
    runtime::Runtime,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    convert::TryInto,
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

#[derive(Debug)]
pub struct Receiver<RT: Runtime> {
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
    base_seq_no: WatchedValue<SeqNumber>,
    recv_queue: RefCell<VecDeque<RT::Buf>>,
    /// Running counter of ack sequence number we have sent to peer.
    /// ToDo: In RFC 793 terms, this appears to be RCV.NXT.  Probably should rename to rcv_nxt or something.
    ack_seq_no: WatchedValue<SeqNumber>,
    /// Our sequence number based on how much data we have sent.
    /// ToDo: Fix above comment, as it is clearly wrong.  It has nothing to do with how much data we have sent.  From
    /// the above ASCII-art diagram, this sequence number is RCV.NXT + RCV.WND?  However, the receive_data function
    /// below behaves as if this sequence number *is* RCV.NXT.
    ///
    recv_seq_no: WatchedValue<SeqNumber>,

    /// Timeout for delayed ACKs.
    ack_delay_timeout: Duration,

    ack_deadline: WatchedValue<Option<Instant>>,

    max_window_size: u32,
    window_scale: u32,

    waker: RefCell<Option<Waker>>,
    out_of_order: RefCell<BTreeMap<SeqNumber, RT::Buf>>,
}

impl<RT: Runtime> Receiver<RT> {
    pub fn new(
        seq_no: SeqNumber,
        ack_delay_timeout: Duration,
        max_window_size: u32,
        window_scale: u32,
    ) -> Self {
        Self {
            base_seq_no: WatchedValue::new(seq_no),
            recv_queue: RefCell::new(VecDeque::with_capacity(RECV_QUEUE_SZ)),
            ack_seq_no: WatchedValue::new(seq_no),
            recv_seq_no: WatchedValue::new(seq_no),
            ack_delay_timeout,
            ack_deadline: WatchedValue::new(None),
            max_window_size,
            window_scale,
            waker: RefCell::new(None),
            out_of_order: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn get_ack_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.ack_seq_no.watch()
    }

    pub fn set_ack_seq_no(&self, new_value: SeqNumber) {
        self.ack_seq_no.set(new_value)
    }

    pub fn get_recv_seq_no(&self) -> (SeqNumber, WatchFuture<SeqNumber>) {
        self.recv_seq_no.watch()
    }

    pub fn get_ack_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.ack_deadline.watch()
    }

    pub fn set_ack_deadline(&self, when: Option<Instant>) {
        self.ack_deadline.set(when);
    }

    pub fn hdr_window_size(&self) -> u16 {
        let bytes_outstanding: u32 = (self.recv_seq_no.get() - self.base_seq_no.get()).into();
        let window_size = self.max_window_size - bytes_outstanding;  // ToDo: Review for underflow.
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
        let ack_seq_no = self.ack_seq_no.get();
        let recv_seq_no = self.recv_seq_no.get();

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
        if self.base_seq_no.get() == self.recv_seq_no.get() {
            *self.waker.borrow_mut() = Some(ctx.waker().clone());
            return Poll::Pending;
        }

        let segment = self
            .recv_queue
            .borrow_mut()
            .pop_front()
            .expect("recv_seq > base_seq without data in queue?");
        self.base_seq_no
            .modify(|b| b + SeqNumber::from(segment.len() as u32));

        Poll::Ready(Ok(segment))
    }

    // ToDo: Improve following comment:
    // This routine appears to take an incoming TCP segment and either add it to the receiver's queue of data that is
    // ready to be read by the user (if the segment contains in-order data) or add it to the proper position in the
    // receiver's store of out-of-order data.  Also, in the in-order case, it updates our receiver's sequence number
    // corresponding to the minumum number allowed for new reception (RCV.NXT in RFC 793 terms).
    //
    pub fn receive_data(&self, seq_no: SeqNumber, buf: RT::Buf, now: Instant) -> Result<(), Fail> {
        let recv_seq_no = self.recv_seq_no.get();

        // Check if new data comes after what we're expecting (i.e. new segment arrived out-of-order).
        if seq_no > recv_seq_no {
            let mut out_of_order = self.out_of_order.borrow_mut();
            // Check if the new data segment's starting sequence number is already in the out-of-order store.
            if !out_of_order.contains_key(&seq_no) {
                // But first, if the out-of-order store contains too many entries, delete later entries until it's ok.
                while out_of_order.len() > MAX_OUT_OF_ORDER {
                    let (&key, _) = out_of_order.iter().rev().next().unwrap();
                    out_of_order.remove(&key);
                }
                // Add the new segment to the out-of-order store.
                out_of_order.insert(seq_no, buf);
                return Err(Fail::Ignored {
                    details: "Out of order segment (reordered)",
                });
            }
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

        // ToDo: This appears to add up all the bytes ready for reading in the recv_queue, each time we get a new
        // segment.  Seems like it would be more efficient to keep a running count of the bytes in the queue that we
        // add/subtract from as we add/remove segments from the queue.
        let unread_bytes = self
            .recv_queue
            .borrow()
            .iter()
            .map(|b| b.len())
            .sum::<usize>();

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

        // Update our receive sequence number (i.e. RCV_NXT) appropriately.
        self.recv_seq_no.modify(|r| r + SeqNumber::from(buf.len() as u32));

        // Push the new segment data onto the end of the receive queue.
        self.recv_queue.borrow_mut().push_back(buf);

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

        // Okay, we've successfully received some new data.  Check if any of the formerly out-of-order data waiting in
        // the out-of-order queue is now in-order.  If so, we can move it to the receive queue.
        let new_recv_seq_no = self.recv_seq_no.get();
        let old_data = {
            let mut out_of_order = self.out_of_order.borrow_mut();
            out_of_order.remove(&new_recv_seq_no)
        };
        // ToDo: There is a bug or two here.  First off, this recursively pulls data off of the out-of-order queue,
        // which could blow the stack if MAX_OUT_OF_ORDER is large.  Secondly, we should be doing this check for
        // out-of-order data thing up above, immediately after we add the new data to our receive queue and before we
        // send the ACK or wake any app-level readers.
        if let Some(old_data) = old_data {
            info!("Recovering out-of-order packet at {}", new_recv_seq_no);
            if let Err(e) = self.receive_data(new_recv_seq_no, old_data, now) {
                info!("Failed to recover out-of-order packet: {:?}", e);
            }
        }

        Ok(())
    }
}
