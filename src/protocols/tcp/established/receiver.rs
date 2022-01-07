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
    num::Wrapping,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

const RECV_QUEUE_SZ: usize = 2048;
const MAX_OUT_OF_ORDER: usize = 16;

#[derive(Debug)]
pub struct Receiver<RT: Runtime> {
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
    base_seq_no: WatchedValue<SeqNumber>,
    recv_queue: RefCell<VecDeque<RT::Buf>>,
    /// Running counter of ack sequence number we have sent to peer.
    ack_seq_no: WatchedValue<SeqNumber>,
    /// Our sequence number based on how much data we have sent.
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

    pub fn get_ack_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.ack_seq_no.watch()
    }

    pub fn set_ack_seq_no(&self, new_value: Wrapping<u32>) {
        self.ack_seq_no.set(new_value)
    }

    pub fn get_recv_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.recv_seq_no.watch()
    }

    pub fn get_ack_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.ack_deadline.watch()
    }

    pub fn set_ack_deadline(&self, when: Option<Instant>) {
        self.ack_deadline.set(when);
    }

    pub fn hdr_window_size(&self) -> u16 {
        let Wrapping(bytes_outstanding) = self.recv_seq_no.get() - self.base_seq_no.get();
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
    pub fn current_ack(&self) -> Option<SeqNumber> {
        let ack_seq_no = self.ack_seq_no.get();
        let recv_seq_no = self.recv_seq_no.get();

        // It is okay if ack_seq_no is greater than the seq number. This can happen when we have
        // ACKed a FIN so our ACK number is +1 greater than our seq number.
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
            .modify(|b| b + Wrapping(segment.len() as u32));

        Poll::Ready(Ok(segment))
    }

    pub fn receive_data(&self, seq_no: SeqNumber, buf: RT::Buf, now: Instant) -> Result<(), Fail> {
        let recv_seq_no = self.recv_seq_no.get();
        if seq_no > recv_seq_no {
            let mut out_of_order = self.out_of_order.borrow_mut();
            if !out_of_order.contains_key(&seq_no) {
                while out_of_order.len() > MAX_OUT_OF_ORDER {
                    let (&key, _) = out_of_order.iter().rev().next().unwrap();
                    out_of_order.remove(&key);
                }
                out_of_order.insert(seq_no, buf);
                return Err(Fail::Ignored {
                    details: "Out of order segment (reordered)",
                });
            }
        }
        if seq_no < recv_seq_no {
            return Err(Fail::Ignored {
                details: "Out of order segment (duplicate)",
            });
        }

        let unread_bytes = self
            .recv_queue
            .borrow()
            .iter()
            .map(|b| b.len())
            .sum::<usize>();
        if unread_bytes + buf.len() > self.max_window_size as usize {
            return Err(Fail::Ignored {
                details: "Full receive window",
            });
        }

        self.recv_seq_no.modify(|r| r + Wrapping(buf.len() as u32));
        self.recv_queue.borrow_mut().push_back(buf);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake()
        }

        // TODO: How do we handle when the other side is in PERSIST state here?
        if self.ack_deadline.get().is_none() {
            self.ack_deadline.set(Some(now + self.ack_delay_timeout));
        }

        let new_recv_seq_no = self.recv_seq_no.get();
        let old_data = {
            let mut out_of_order = self.out_of_order.borrow_mut();
            out_of_order.remove(&new_recv_seq_no)
        };
        if let Some(old_data) = old_data {
            info!("Recovering out-of-order packet at {}", new_recv_seq_no);
            if let Err(e) = self.receive_data(new_recv_seq_no, old_data, now) {
                info!("Failed to recover out-of-order packet: {:?}", e);
            }
        }

        Ok(())
    }
}
