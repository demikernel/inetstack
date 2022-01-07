// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod acknowledger;
mod closer;
mod retransmitter;
mod sender;

use self::{
    acknowledger::acknowledger, closer::connection_terminated, retransmitter::retransmitter,
    sender::sender,
};
use super::{ControlBlock, State};
use crate::{file_table::FileDescriptor, runtime::Runtime};
use futures::channel::mpsc;
use futures::FutureExt;
use std::{future::Future, rc::Rc};

pub type BackgroundFuture<RT> = impl Future<Output = ()>;

pub fn background<RT: Runtime>(
    cb: Rc<ControlBlock<RT>>,
    fd: FileDescriptor,
    _dead_socket_tx: mpsc::UnboundedSender<FileDescriptor>,
) -> BackgroundFuture<RT> {
    async move {
        let acknowledger = acknowledger(cb.clone()).fuse();
        futures::pin_mut!(acknowledger);

        let retransmitter = retransmitter(cb.clone()).fuse();
        futures::pin_mut!(retransmitter);

        let sender = sender(cb.clone()).fuse();
        futures::pin_mut!(sender);

        let closer = connection_terminated(cb).fuse();
        futures::pin_mut!(closer);

        let r = futures::select_biased! {
            r = acknowledger => r,
            r = retransmitter => r,
            r = sender => r,
            r = closer => r,
        };
        error!("Connection (fd {}) terminated: {:?}", fd, r);

        // TODO Properly clean up Peer state for this connection.
        // dead_socket_tx
        //     .unbounded_send(fd)
        //     .expect("Failed to terminate connection");
    }
}
