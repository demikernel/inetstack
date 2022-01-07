// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::super::{ctrlblk::ControlBlock, sender::UnackedSegment};
use crate::{fail::Fail, runtime::Runtime};
use futures::FutureExt;
use std::{cmp, num::Wrapping, rc::Rc, time::Duration};

pub async fn sender<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    'top: loop {
        // First, check to see if there's any unsent data.
        let (unsent_seq, unsent_seq_changed) = cb.get_unsent_seq_no();
        futures::pin_mut!(unsent_seq_changed);

        // TODO: We don't need to watch this value since we're the only mutator.
        let (sent_seq, sent_seq_changed) = cb.get_sent_seq_no();
        futures::pin_mut!(sent_seq_changed);

        if sent_seq == unsent_seq {
            futures::select_biased! {
                _ = unsent_seq_changed => continue 'top,
                _ = sent_seq_changed => continue 'top,
            }
        }

        // Okay, we know we have some unsent data past this point. Next, check to see that the
        // remote side has available window.
        let (win_sz, win_sz_changed) = cb.get_window_size();
        futures::pin_mut!(win_sz_changed);

        // If we don't have any window size at all, we need to transition to PERSIST state and
        // repeatedly send window probes until window opens up.
        if win_sz == 0 {
            let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;
            let buf = cb
                .pop_one_unsent_byte()
                .unwrap_or_else(|| panic!("No unsent data? {}, {}", sent_seq, unsent_seq));

            cb.modify_sent_seq_no(|s| s + Wrapping(1));
            let unacked_segment = UnackedSegment {
                bytes: buf.clone(),
                initial_tx: Some(cb.rt().now()),
            };
            cb.push_unacked_segment(unacked_segment);

            let mut header = cb.tcp_header();
            header.seq_num = sent_seq;
            cb.emit(header, buf.clone(), remote_link_addr);

            // Note that we loop here *forever*, exponentially backing off.
            // TODO: Use the correct PERSIST state timer here.
            let mut timeout = Duration::from_secs(1);
            loop {
                futures::select_biased! {
                    _ = win_sz_changed => continue 'top,
                    _ = cb.rt().wait(timeout).fuse() => {
                        timeout *= 2;
                    }
                }
                // Retransmit our window probe.
                let mut header = cb.tcp_header();
                header.seq_num = sent_seq;
                cb.emit(header, buf.clone(), remote_link_addr);
            }
        }

        // The remote window is nonzero, but there still may not be room.
        let (base_seq, base_seq_changed) = cb.get_base_seq_no();
        futures::pin_mut!(base_seq_changed);

        // Before we get cwnd for the check, we prompt it to shrink it if the connection has been idle
        cb.congestion_ctrl_on_cwnd_check_before_send();
        let (cwnd, cwnd_changed) = cb.congestion_ctrl_watch_cwnd();
        futures::pin_mut!(cwnd_changed);

        // The limited transmit algorithm may increase the effective size of cwnd by up to 2 * mss
        let (ltci, ltci_changed) = cb.congestion_ctrl_watch_limited_transmit_cwnd_increase();
        futures::pin_mut!(ltci_changed);

        let effective_cwnd = cwnd + ltci;
        let next_buf_size = cb.unsent_top_size().expect("no buffer in unsent queue");

        let Wrapping(sent_data) = sent_seq - base_seq;
        if win_sz <= (sent_data + next_buf_size as u32)
            || effective_cwnd <= sent_data
            || (effective_cwnd - sent_data) <= cb.get_mss() as u32
        {
            futures::select_biased! {
                _ = base_seq_changed => continue 'top,
                _ = sent_seq_changed => continue 'top,
                _ = win_sz_changed => continue 'top,
                _ = cwnd_changed => continue 'top,
                _ = ltci_changed => continue 'top,
            }
        }

        // Past this point we have data to send and it's valid to send it!

        // TODO: Nagle's algorithm
        // TODO: Silly window syndrome
        let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;

        // Form an outgoing packet.
        let max_size = cmp::min(
            cmp::min((win_sz - sent_data) as usize, cb.get_mss()),
            (effective_cwnd - sent_data) as usize,
        );
        let segment_data = cb
            .pop_unsent_segment(max_size)
            .expect("No unsent data with sequence number gap?");
        let segment_data_len = segment_data.len();
        assert!(segment_data_len > 0);

        let rto: Duration = cb.current_rto();
        cb.congestion_ctrl_on_send(rto, sent_data);

        let mut header = cb.tcp_header();
        header.seq_num = sent_seq;
        cb.emit(header, segment_data.clone(), remote_link_addr);

        cb.modify_sent_seq_no(|s| s + Wrapping(segment_data_len as u32));
        let unacked_segment = UnackedSegment {
            bytes: segment_data,
            initial_tx: Some(cb.rt().now()),
        };
        cb.push_unacked_segment(unacked_segment);

        let (retransmit_deadline, _) = cb.get_retransmit_deadline();
        if retransmit_deadline.is_none() {
            let rto = cb.rto_estimate();
            cb.set_retransmit_deadline(Some(cb.rt().now() + rto));
        }
    }
}
