// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Defines functions to be called during the TCP connection termination process.

use super::{ControlBlock, State};
use crate::{
    fail::Fail,
    runtime::{Runtime, RuntimeBuf},
};
use futures::FutureExt;
use std::{num::Wrapping, rc::Rc};

//==============================================================================

async fn active_send_fin<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();

        // Wait until we receive a FIN.
        if st != State::ActiveClose {
            st_changed.await;
            continue;
        }

        // Wait for `sent_seq_no` to catch up to `unsent_seq_no` and
        // then send a FIN segment.
        let (sent_seq, sent_seq_changed) = cb.get_sent_seq_no();
        let (unsent_seq, _) = cb.get_unsent_seq_no();
        if sent_seq != unsent_seq {
            sent_seq_changed.await;
            continue;
        }

        // TODO: When do we retransmit this?
        let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;
        let mut header = cb.tcp_header();
        header.seq_num = sent_seq;
        header.fin = true;
        cb.emit(header, RT::Buf::empty(), remote_link_addr);

        cb.set_state(State::FinWait1);
    }
}

//==============================================================================

async fn active_ack_fin<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();

        if st != State::FinWait3 && st != State::TimeWait1 && st != State::Closing1 {
            st_changed.await;
            continue;
        }

        // Wait for all data to be acknowledged.
        let (ack_seq, ack_seq_changed) = cb.get_last_ack_no();
        let (recv_seq, _) = cb.get_last_recv_seq_no();
        if ack_seq != recv_seq {
            ack_seq_changed.await;
            continue;
        }

        // Send ACK segment for FIN.
        let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;
        let mut header = cb.tcp_header();

        // ACK replies to FIN are special as their ack sequence number should be set to +1 the
        // received seq number even though there is no payload.
        header.ack = true;
        header.ack_num = recv_seq + Wrapping(1);
        cb.emit(header, RT::Buf::empty(), remote_link_addr);

        if st == State::Closing1 {
            cb.set_state(State::Closing2)
        } else {
            cb.set_state(State::TimeWait2);
        }
    }
}

//==============================================================================

/// Awaits until connection terminates by our four-way handshake.
async fn active_wait_2msl<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();

        if st != State::TimeWait2 {
            st_changed.await;
            continue;
        }

        // TODO: Wait for 2*MSL if active close.
        return Err(Fail::ConnectionAborted {});
    }
}

//==============================================================================

async fn passive_close<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();

        // Wait until we receive a FIN.
        if st != State::PassiveClose {
            st_changed.await;
            continue;
        }

        // Wait for all data to be acknowledged.
        let (ack_seq, ack_seq_changed) = cb.get_last_ack_no();
        let (recv_seq, _) = cb.get_last_recv_seq_no();
        if ack_seq != recv_seq {
            ack_seq_changed.await;
            continue;
        }

        // Send ACK segment for FIN.
        let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;
        let mut header = cb.tcp_header();
        header.ack = true;
        header.ack_num = recv_seq + Wrapping(1);
        cb.emit(header, RT::Buf::empty(), remote_link_addr);

        cb.set_state(State::CloseWait1);
    }
}

//==============================================================================

async fn passive_send_fin<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();

        if st != State::CloseWait2 {
            st_changed.await;
            continue;
        }

        // Wait for `sent_seq_no` to catch up to `unsent_seq_no` and then send a FIN segment.
        let (sent_seq, sent_seq_changed) = cb.get_sent_seq_no();
        let (unsent_seq, _) = cb.get_unsent_seq_no();
        if sent_seq != unsent_seq {
            sent_seq_changed.await;
            continue;
        }

        let remote_link_addr = cb.arp().query(cb.get_remote().address()).await?;
        let mut header = cb.tcp_header();
        header.seq_num = sent_seq;
        header.fin = true;
        cb.emit(header, RT::Buf::empty(), remote_link_addr);

        cb.set_state(State::LastAck);
    }
}

//==============================================================================

async fn passive_wait_fin_ack<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    loop {
        let (st, st_changed) = cb.get_state();
        if st != State::Closed {
            st_changed.await;
            continue;
        }

        return Err(Fail::ConnectionAborted {});
    }
}

/// Launches various closures having to do with connection termination. Neither `active_ack_fin`
/// nor `active_send_fin` terminate so the only way to return is via `active_wait_2msl`.
pub async fn connection_terminated<RT: Runtime>(cb: Rc<ControlBlock<RT>>) -> Result<!, Fail> {
    futures::select_biased! {
        r = active_send_fin(cb.clone()).fuse() => r,
        r = active_ack_fin(cb.clone()).fuse() => r,
        r = active_wait_2msl(cb.clone()).fuse() => r,
        r = passive_close(cb.clone()).fuse() => r,
        r = passive_send_fin(cb.clone()).fuse() => r,
        r = passive_wait_fin_ack(cb.clone()).fuse() => r,
    }
}
