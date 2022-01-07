// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::ControlBlock;
use crate::{fail::Fail, runtime::Runtime};
use futures::{
    future::{self, Either},
    FutureExt,
};
use std::{rc::Rc, time::Duration};

pub enum RetransmitCause {
    TimeOut,
    FastRetransmit,
}

async fn retransmit<RT: Runtime>(
    cause: RetransmitCause,
    cb: &Rc<ControlBlock<RT>>,
) -> Result<(), Fail> {
    // Pop unack'ed segment.
    let mut segment = match cb.pop_unacked_segment() {
        Some(s) => s,
        None => {
            warn!("Retransmission with empty unacknowledged queue");
            return Ok(());
        }
    };

    // TODO: Repacketization

    // NOTE: Congestion Control Don't think we record a failure on Fast Retransmit, but can't find a definitive source.
    match cause {
        RetransmitCause::TimeOut => cb.rto_record_failure(),
        RetransmitCause::FastRetransmit => (),
    };

    // Our retransmission timer fired, so we need to resend a packet.
    let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;

    // Unset the initial timestamp so we don't use this for RTT estimation.
    segment.initial_tx.take();

    let (seq_no, _) = cb.get_base_seq_no();
    let mut header = cb.tcp_header();
    header.seq_num = seq_no;
    cb.emit(header, segment.bytes.clone(), remote_link_addr);

    // Set new retransmit deadline
    let rto: Duration = cb.rto_estimate();
    let deadline = cb.rt().now() + rto;
    cb.set_retransmit_deadline(Some(deadline));
    Ok(())
}

pub async fn retransmitter<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        // Pin future for timeout retransmission.
        let (rtx_deadline, rtx_deadline_changed) = cb.get_retransmit_deadline();
        futures::pin_mut!(rtx_deadline_changed);
        let rtx_future = match rtx_deadline {
            Some(t) => Either::Left(cb.rt().wait_until(t).fuse()),
            None => Either::Right(future::pending()),
        };
        futures::pin_mut!(rtx_future);

        // Pin future for fast retransmission.
        let (rtx_fast_retransmit, rtx_fast_retransmit_changed) =
            cb.congestion_ctrl_watch_retransmit_now_flag();
        if rtx_fast_retransmit {
            cb.congestion_ctrl_on_fast_retransmit();
            retransmit(RetransmitCause::FastRetransmit, &cb).await?;
            continue;
        }
        futures::pin_mut!(rtx_fast_retransmit_changed);

        futures::select_biased! {
            _ = rtx_deadline_changed => continue,
            _ = rtx_fast_retransmit_changed => continue,
            _ = rtx_future => {
                let (base_seq_no, _) = cb.get_base_seq_no();
                cb.congestion_ctrl_on_rto(base_seq_no);
                retransmit(RetransmitCause::TimeOut, &cb).await?;
            },
        }
    }
}
