// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod background;
mod ctrlblk;
mod sender;

pub use self::ctrlblk::ControlBlock;
pub use self::ctrlblk::State;
pub use self::sender::congestion_ctrl as cc;

use self::background::background;
use crate::{
    fail::Fail,
    file_table::FileDescriptor,
    protocols::{ipv4, tcp::segment::TcpHeader},
    runtime::Runtime,
    scheduler::SchedulerHandle,
};
use futures::channel::mpsc;
use std::{
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

pub struct EstablishedSocket<RT: Runtime> {
    pub cb: Rc<ControlBlock<RT>>,
    #[allow(unused)]
    background_work: SchedulerHandle,
}

impl<RT: Runtime> EstablishedSocket<RT> {
    pub fn new(
        cb: ControlBlock<RT>,
        fd: FileDescriptor,
        dead_socket_tx: mpsc::UnboundedSender<FileDescriptor>,
    ) -> Self {
        let cb = Rc::new(cb);
        let future = background(cb.clone(), fd, dead_socket_tx);
        let handle = cb.rt().spawn(future);
        Self {
            cb: cb.clone(),
            background_work: handle,
        }
    }

    pub fn receive(&self, header: &TcpHeader, data: RT::Buf) {
        self.cb.receive(header, data)
    }

    pub fn send(&self, buf: RT::Buf) -> Result<(), Fail> {
        self.cb.send(buf)
    }

    pub fn poll_recv(&self, ctx: &mut Context) -> Poll<Result<RT::Buf, Fail>> {
        self.cb.poll_recv(ctx)
    }

    pub fn close(&self) -> Result<(), Fail> {
        self.cb.close()
    }

    pub fn remote_mss(&self) -> usize {
        self.cb.remote_mss()
    }

    pub fn current_rto(&self) -> Duration {
        self.cb.rto_current()
    }

    pub fn endpoints(&self) -> (ipv4::Endpoint, ipv4::Endpoint) {
        (self.cb.get_local(), self.cb.get_remote())
    }
}
