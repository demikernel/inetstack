// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod congestion_ctrl;
mod rto;

use super::ControlBlock;
use crate::{
    collections::watched::{WatchFuture, WatchedValue},
    fail::Fail,
    protocols::tcp::SeqNumber,
    runtime::{Runtime, RuntimeBuf},
};
use congestion_ctrl as cc;
use rto::RtoCalculator;
use std::{
    boxed::Box,
    cell::RefCell,
    collections::VecDeque,
    convert::TryInto,
    fmt,
    num::Wrapping,
    time::{Duration, Instant},
};

pub struct UnackedSegment<RT: Runtime> {
    pub bytes: RT::Buf,
    // Set to `None` on retransmission to implement Karn's algorithm.
    pub initial_tx: Option<Instant>,
}

/// Hard limit for unsent queue.
const UNSENT_QUEUE_CUTOFF: usize = 1024;

pub struct Sender<RT: Runtime> {
    // TODO: Just use Figure 5 from RFC 793 here.
    //
    //                    |------------window_size------------|
    //
    //               base_seq_no               sent_seq_no           unsent_seq_no
    //                    v                         v                      v
    // ... ---------------|-------------------------|----------------------| (unavailable)
    //       acknowledged        unacknowledged     ^        unsent
    //
    base_seq_no: WatchedValue<SeqNumber>,
    unacked_queue: RefCell<VecDeque<UnackedSegment<RT>>>,
    sent_seq_no: WatchedValue<SeqNumber>,
    unsent_queue: RefCell<VecDeque<RT::Buf>>,
    unsent_seq_no: WatchedValue<SeqNumber>,

    window_size: WatchedValue<u32>,
    // RFC 1323: Number of bits to shift advertised window, defaults to zero.
    window_scale: u8,

    mss: usize,

    retransmit_deadline: WatchedValue<Option<Instant>>,
    rto: RefCell<RtoCalculator>,

    congestion_ctrl: Box<dyn cc::CongestionControl<RT>>,
}

impl<RT: Runtime> fmt::Debug for Sender<RT> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Sender")
            .field("base_seq_no", &self.base_seq_no)
            .field("sent_seq_no", &self.sent_seq_no)
            .field("unsent_seq_no", &self.unsent_seq_no)
            .field("window_size", &self.window_size)
            .field("window_scale", &self.window_scale)
            .field("mss", &self.mss)
            .field("retransmit_deadline", &self.retransmit_deadline)
            .field("rto", &self.rto)
            .finish()
    }
}

impl<RT: Runtime> Sender<RT> {
    pub fn new(
        seq_no: SeqNumber,
        window_size: u32,
        window_scale: u8,
        mss: usize,
        cc_constructor: cc::CongestionControlConstructor<RT>,
        congestion_control_options: Option<cc::Options>,
    ) -> Self {
        Self {
            base_seq_no: WatchedValue::new(seq_no),
            unacked_queue: RefCell::new(VecDeque::new()),
            sent_seq_no: WatchedValue::new(seq_no),
            unsent_queue: RefCell::new(VecDeque::new()),
            unsent_seq_no: WatchedValue::new(seq_no),

            window_size: WatchedValue::new(window_size),
            window_scale,
            mss,

            retransmit_deadline: WatchedValue::new(None),
            rto: RefCell::new(RtoCalculator::new()),

            congestion_ctrl: cc_constructor(mss, seq_no, congestion_control_options),
        }
    }

    pub fn get_mss(&self) -> usize {
        self.mss
    }

    pub fn get_window_size(&self) -> (u32, WatchFuture<u32>) {
        self.window_size.watch()
    }

    pub fn get_base_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.base_seq_no.watch()
    }

    pub fn get_sent_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.sent_seq_no.watch()
    }

    pub fn modify_sent_seq_no(&self, f: impl FnOnce(Wrapping<u32>) -> Wrapping<u32>) {
        self.sent_seq_no.modify(f)
    }

    pub fn get_unsent_seq_no(&self) -> (Wrapping<u32>, WatchFuture<Wrapping<u32>>) {
        self.unsent_seq_no.watch()
    }

    pub fn get_retransmit_deadline(&self) -> (Option<Instant>, WatchFuture<Option<Instant>>) {
        self.retransmit_deadline.watch()
    }

    pub fn set_retransmit_deadline(&self, when: Option<Instant>) {
        self.retransmit_deadline.set(when);
    }

    pub fn pop_unacked_segment(&self) -> Option<UnackedSegment<RT>> {
        self.unacked_queue.borrow_mut().pop_front()
    }

    pub fn push_unacked_segment(&self, segment: UnackedSegment<RT>) {
        self.unacked_queue.borrow_mut().push_back(segment)
    }

    pub fn rto_estimate(&self) -> Duration {
        self.rto.borrow().estimate()
    }

    pub fn rto_record_failure(&self) {
        self.rto.borrow_mut().record_failure()
    }

    pub fn send(&self, buf: RT::Buf, cb: &ControlBlock<RT>) -> Result<(), Fail> {
        let buf_len: u32 = buf.len().try_into().map_err(|_| Fail::Ignored {
            details: "Buffer too large",
        })?;

        let win_sz = self.window_size.get();
        let base_seq = self.base_seq_no.get();
        let sent_seq = self.sent_seq_no.get();
        let Wrapping(sent_data) = sent_seq - base_seq;

        // Fast path: Try to send the data immediately.
        let in_flight_after_send = sent_data + buf_len;

        // Before we get cwnd for the check, we prompt it to shrink it if the connection has been idle
        self.congestion_ctrl.on_cwnd_check_before_send();
        let cwnd = self.congestion_ctrl.get_cwnd();
        // The limited transmit algorithm can increase the effective size of cwnd by up to 2MSS
        let effective_cwnd = cwnd + self.congestion_ctrl.get_limited_transmit_cwnd_increase();

        if self.unsent_queue.borrow().len() == 0 {
            if win_sz > 0
                && win_sz >= in_flight_after_send
                && effective_cwnd >= in_flight_after_send
            {
                if let Some(remote_link_addr) = cb.arp().try_query(cb.get_remote().address()) {
                    // This hook is primarily intended to record the last time we sent data, so we can later tell if the connection has been idle

                    let rto: Duration = self.current_rto();
                    self.congestion_ctrl.on_send(rto, sent_data);

                    let mut header = cb.tcp_header();
                    header.seq_num = sent_seq;
                    cb.emit(header, buf.clone(), remote_link_addr);

                    self.unsent_seq_no.modify(|s| s + Wrapping(buf_len));
                    self.sent_seq_no.modify(|s| s + Wrapping(buf_len));
                    let unacked_segment = UnackedSegment {
                        bytes: buf,
                        initial_tx: Some(cb.rt().now()),
                    };
                    self.unacked_queue.borrow_mut().push_back(unacked_segment);
                    if self.retransmit_deadline.get().is_none() {
                        let rto = self.rto.borrow().estimate();
                        self.retransmit_deadline.set(Some(cb.rt().now() + rto));
                    }
                    return Ok(());
                }
            }
        }

        // Too fast.
        if self.unsent_queue.borrow().len() > UNSENT_QUEUE_CUTOFF {
            return Err(Fail::ResourceBusy {
                details: "too many packets to send",
            });
        }

        // Slow path: Delegating sending the data to background processing.
        self.unsent_queue.borrow_mut().push_back(buf);
        self.unsent_seq_no.modify(|s| s + Wrapping(buf_len));

        Ok(())
    }

    pub fn remote_ack(&self, ack_seq_no: SeqNumber, now: Instant) -> Result<(), Fail> {
        let base_seq_no = self.base_seq_no.get();
        let sent_seq_no = self.sent_seq_no.get();

        let bytes_outstanding = sent_seq_no - base_seq_no;
        let bytes_acknowledged = ack_seq_no - base_seq_no;

        if bytes_acknowledged > bytes_outstanding {
            return Err(Fail::Ignored {
                details: "ACK is outside of send window",
            });
        }

        let rto: Duration = self.current_rto();
        self.congestion_ctrl
            .on_ack_received(rto, base_seq_no, sent_seq_no, ack_seq_no);
        if bytes_acknowledged == Wrapping(0) {
            return Ok(());
        }

        if ack_seq_no == sent_seq_no {
            // If we've acknowledged all sent data, turn off the retransmit timer.
            self.retransmit_deadline.set(None);
        } else {
            // Otherwise, set it to the current RTO.
            let deadline = now + self.rto.borrow().estimate();
            self.retransmit_deadline.set(Some(deadline));
        }

        // TODO: Do acks need to be on segment boundaries? How does this interact with repacketization?
        let mut bytes_remaining = bytes_acknowledged.0 as usize;
        while let Some(segment) = self.unacked_queue.borrow_mut().pop_front() {
            if segment.bytes.len() > bytes_remaining {
                // TODO: We need to close the connection in this case.
                return Err(Fail::Ignored {
                    details: "ACK isn't on segment boundary",
                });
            }
            bytes_remaining -= segment.bytes.len();

            // Add sample for RTO if not a retransmission
            // TODO: TCP timestamp support.
            if let Some(initial_tx) = segment.initial_tx {
                self.rto.borrow_mut().add_sample(now - initial_tx);
            }
            if bytes_remaining == 0 {
                break;
            }
        }
        self.base_seq_no.modify(|b| b + bytes_acknowledged);
        let new_base_seq_no = self.base_seq_no.get();
        if new_base_seq_no < base_seq_no {
            // We've wrapped around, and so we need to do some bookkeeping
            self.congestion_ctrl.on_base_seq_no_wraparound();
        }

        Ok(())
    }

    pub fn pop_one_unsent_byte(&self) -> Option<RT::Buf> {
        let mut queue = self.unsent_queue.borrow_mut();

        let buf = queue.front_mut()?;
        let mut cloned_buf = buf.clone();
        let buf_len = buf.len();

        // Pop one byte off the buf still in the queue and all but one of the bytes on our clone.
        buf.adjust(1);
        cloned_buf.trim(buf_len - 1);

        Some(cloned_buf)
    }

    pub fn pop_unsent(&self, max_bytes: usize) -> Option<RT::Buf> {
        // TODO: Use a scatter/gather array to coalesce multiple buffers into a single segment.
        let mut unsent_queue = self.unsent_queue.borrow_mut();
        let mut buf = unsent_queue.pop_front()?;
        let buf_len = buf.len();

        if buf_len > max_bytes {
            let mut cloned_buf = buf.clone();

            buf.adjust(max_bytes);
            cloned_buf.trim(buf_len - max_bytes);

            unsent_queue.push_front(buf);
            buf = cloned_buf;
        }
        Some(buf)
    }

    pub fn top_size_unsent(&self) -> Option<usize> {
        let unsent_queue = self.unsent_queue.borrow_mut();
        Some(unsent_queue.front()?.len())
    }

    pub fn update_remote_window(&self, window_size_hdr: u16) -> Result<(), Fail> {
        // TODO: Is this the right check?
        let window_size = (window_size_hdr as u32)
            .checked_shl(self.window_scale as u32)
            .ok_or(Fail::Ignored {
                details: "Window size overflow",
            })?;

        debug!(
            "Updating window size -> {} (hdr {}, scale {})",
            window_size, window_size_hdr, self.window_scale
        );
        self.window_size.set(window_size);

        Ok(())
    }

    pub fn remote_mss(&self) -> usize {
        self.mss
    }

    pub fn current_rto(&self) -> Duration {
        self.rto.borrow().estimate()
    }

    pub fn congestion_ctrl_watch_retransmit_now_flag(&self) -> (bool, WatchFuture<bool>) {
        self.congestion_ctrl.watch_retransmit_now_flag()
    }

    pub fn congestion_ctrl_on_fast_retransmit(&self) {
        self.congestion_ctrl.on_fast_retransmit()
    }

    pub fn congestion_ctrl_on_rto(&self, base_seq_no: Wrapping<u32>) {
        self.congestion_ctrl.on_rto(base_seq_no)
    }

    pub fn congestion_ctrl_on_send(&self, rto: Duration, num_sent_bytes: u32) {
        self.congestion_ctrl.on_send(rto, num_sent_bytes)
    }

    pub fn congestion_ctrl_on_cwnd_check_before_send(&self) {
        self.congestion_ctrl.on_cwnd_check_before_send()
    }

    pub fn congestion_ctrl_watch_cwnd(&self) -> (u32, WatchFuture<u32>) {
        self.congestion_ctrl.watch_cwnd()
    }

    pub fn congestion_ctrl_watch_limited_transmit_cwnd_increase(&self) -> (u32, WatchFuture<u32>) {
        self.congestion_ctrl.watch_limited_transmit_cwnd_increase()
    }
}
