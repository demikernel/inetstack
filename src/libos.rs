// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LibOS defines the PDPIX (portable data plane interface) abstraction. PDPIX centers around
//! the IO Queue abstraction, thus providing a standard interface for different kernel bypass
//! mechanisms.
use crate::{
    engine::Engine,
    fail::Fail,
    file_table::FileDescriptor,
    interop::{dmtr_qresult_t, dmtr_sgarray_t},
    operations::OperationResult,
    protocols::ipv4::Endpoint,
    protocols::Protocol,
    runtime::Runtime,
    scheduler::{Operation, SchedulerHandle},
};
use libc::c_int;
use must_let::must_let;
use std::time::Instant;

#[cfg(feature = "profiler")]
use perftools::timer;

const TIMER_RESOLUTION: usize = 64;
const MAX_RECV_ITERS: usize = 2;

/// Queue Token for our IO Queue abstraction. Analogous to a file descriptor in POSIX.
pub type QToken = u64;

pub struct LibOS<RT: Runtime> {
    engine: Engine<RT>,
    rt: RT,
    ts_iters: usize,
}

impl<RT: Runtime> LibOS<RT> {
    pub fn new(rt: RT) -> Result<Self, Fail> {
        let engine = Engine::new(rt.clone())?;
        Ok(Self {
            engine,
            rt,
            ts_iters: 0,
        })
    }

    pub fn rt(&self) -> &RT {
        &self.rt
    }

    ///
    /// **Brief**
    ///
    /// Creates an endpoint for communication and returns a file descriptor that
    /// refers to that endpoint. The file descriptor returned by a successful
    /// call will be the lowest numbered file descriptor not currently open for
    /// the process.
    ///
    /// The domain argument specifies a communication domain; this selects the
    /// protocol family which will be used for communication. These families are
    /// defined in the libc crate. Currently, the following families are supported:
    ///
    /// - AF_INET Internet Protocol Version 4 (IPv4)
    ///
    /// **Return Vale**
    ///
    /// Upon successful completion, a file descriptor for the newly created
    /// socket is returned. Upon failure, `Fail` is returned instead.
    ///
    pub fn socket(
        &mut self,
        domain: c_int,
        socket_type: c_int,
        _protocol: c_int,
    ) -> Result<FileDescriptor, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::socket");
        trace!(
            "socket(): domain={:?} type={:?} protocol={:?}",
            domain,
            socket_type,
            _protocol
        );
        if domain != libc::AF_INET {
            return Err(Fail::AddressFamilySupport {});
        }
        let engine_protocol = match socket_type {
            libc::SOCK_STREAM => Protocol::Tcp,
            libc::SOCK_DGRAM => Protocol::Udp,
            _ => return Err(Fail::SocketTypeSupport {}),
        };
        Ok(self.engine.socket(engine_protocol))
    }

    ///
    /// **Brief**
    ///
    /// Binds the socket referred to by `fd` to the local endpoint specified by
    /// `local`.
    ///
    /// **Return Value**
    ///
    /// Upon successful completion, `Ok(())` is returned. Upon failure, `Fail` is
    /// returned instead.
    ///
    pub fn bind(&mut self, fd: FileDescriptor, local: Endpoint) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::bind");
        trace!("bind(): fd={:?} local={:?}", fd, local);
        self.engine.bind(fd, local)
    }

    ///
    /// **Brief**
    ///
    /// Marks the socket referred to by `fd` as a socket that will be used to
    /// accept incoming connection requests using [accept](Self::accept). The `fd` should
    /// refer to a socket of type `SOCK_STREAM`. The `backlog` argument defines
    /// the maximum length to which the queue of pending connections for `fd`
    /// may grow. If a connection request arrives when the queue is full, the
    /// client may receive an error with an indication that the connection was
    /// refused.
    ///
    /// **Return Value**
    ///
    /// Upon successful completion, `Ok(())` is returned. Upon failure, `Fail` is
    /// returned instead.
    ///
    pub fn listen(&mut self, fd: FileDescriptor, backlog: usize) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::listen");
        trace!("listen(): fd={:?} backlog={:?}", fd, backlog);
        if backlog == 0 {
            return Err(Fail::Invalid {
                details: "backlog length",
            });
        }
        self.engine.listen(fd, backlog)
    }

    ///
    /// **Brief**
    ///
    /// Accepts an incoming connection request on the queue of pending
    /// connections for the listening socket referred to by `fd`.
    ///
    /// **Return Value**
    ///
    /// Upon successful completion, a queue token is returned. This token can be
    /// used to wait for a connection request to arrive. Upon failure, `Fail` is
    /// returned instead.
    ///
    pub fn accept(&mut self, fd: FileDescriptor) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::accept");
        trace!("accept(): {:?}", fd);
        match self.engine.accept(fd) {
            Ok(future) => Ok(self.rt.scheduler().insert(future).into_raw()),
            Err(fail) => Err(fail),
        }
    }

    ///
    /// **Brief**
    ///
    /// Connects the socket referred to by `fd` to the remote endpoint specified by `remote`.
    ///
    /// **Return Value**
    ///
    /// Upon successful completion, a queue token is returned. This token can be
    /// used to push and pop data to/from the queue that connects the local and
    /// remote endpoints. Upon failure, `Fail` is
    /// returned instead.
    ///
    pub fn connect(&mut self, fd: FileDescriptor, remote: Endpoint) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::connect");
        trace!("connect(): fd={:?} remote={:?}", fd, remote);
        let future = self.engine.connect(fd, remote)?;
        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    ///
    /// **Brief**
    ///
    /// Closes a connection referred to by `fd`.
    ///
    /// **Return Value**
    ///
    /// Upon successful completion, `Ok(())` is returned. Upon failure, `Fail` is
    /// returned instead.
    ///
    pub fn close(&mut self, fd: FileDescriptor) -> Result<(), Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::close");
        trace!("close(): fd={:?}", fd);
        self.engine.close(fd)
    }

    /// Create a push request for Demikernel to asynchronously write data from `sga` to the
    /// IO connection represented by `fd`. This operation returns immediately with a `QToken`.
    /// The data has been written when [`wait`ing](Self::wait) on the QToken returns.
    pub fn push(&mut self, fd: FileDescriptor, sga: &dmtr_sgarray_t) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::push");
        trace!("push(): fd={:?}", fd);
        let buf = self.rt.clone_sgarray(sga);
        if buf.len() == 0 {
            return Err(Fail::Invalid {
                details: "zero-length buffer",
            });
        }
        let future = self.engine.push(fd, buf)?;
        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    /// Similar to [push](Self::push) but uses a [Runtime]-specific buffer instead of the
    /// [dmtr_sgarray_t].
    pub fn push2(&mut self, fd: FileDescriptor, buf: RT::Buf) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::push2");
        trace!("push2(): fd={:?}", fd);
        if buf.len() == 0 {
            return Err(Fail::Invalid {
                details: "zero-length buffer",
            });
        }
        let future = self.engine.push(fd, buf)?;
        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    pub fn pushto(
        &mut self,
        fd: FileDescriptor,
        sga: &dmtr_sgarray_t,
        to: Endpoint,
    ) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::pushto");
        let buf = self.rt.clone_sgarray(sga);
        if buf.len() == 0 {
            return Err(Fail::Invalid {
                details: "zero-length buffer",
            });
        }
        let future = self.engine.pushto(fd, buf, to)?;
        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    pub fn pushto2(
        &mut self,
        fd: FileDescriptor,
        buf: RT::Buf,
        to: Endpoint,
    ) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::pushto2");
        if buf.len() == 0 {
            return Err(Fail::Invalid {
                details: "zero-length buffer",
            });
        }
        let future = self.engine.pushto(fd, buf, to)?;
        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    ///
    /// **Brief**
    ///
    /// Invalidates the queue token referred to by `qt`. Any operations on this
    /// operations will fail.
    ///
    pub fn drop_qtoken(&mut self, qt: QToken) {
        #[cfg(feature = "profiler")]
        timer!("catnip::drop_qtoken");
        drop(self.rt.scheduler().from_raw_handle(qt).unwrap());
    }

    /// Create a pop request to write data from IO connection represented by `fd` into a buffer
    /// allocated by the application.
    pub fn pop(&mut self, fd: FileDescriptor) -> Result<QToken, Fail> {
        #[cfg(feature = "profiler")]
        timer!("catnip::pop");

        trace!("pop(): fd={:?}", fd);

        let future = self.engine.pop(fd)?;

        Ok(self.rt.scheduler().insert(future).into_raw())
    }

    // If this returns a result, `qt` is no longer valid.
    pub fn poll(&mut self, qt: QToken) -> Option<dmtr_qresult_t> {
        #[cfg(feature = "profiler")]
        timer!("catnip::poll");
        trace!("poll(): qt={:?}", qt);
        self.poll_bg_work();
        let handle = match self.rt.scheduler().from_raw_handle(qt) {
            None => {
                panic!("Invalid handle {}", qt);
            }
            Some(h) => h,
        };
        if !handle.has_completed() {
            handle.into_raw();
            return None;
        }
        let (qd, r) = self.take_operation(handle);
        Some(dmtr_qresult_t::pack(&self.rt, r, qd, qt))
    }

    /// Block until request represented by `qt` is finished returning the results of this request.
    pub fn wait(&mut self, qt: QToken) -> dmtr_qresult_t {
        #[cfg(feature = "profiler")]
        timer!("catnip::wait");
        trace!("wait(): qt={:?}", qt);
        let (qd, result) = self.wait2(qt);
        dmtr_qresult_t::pack(&self.rt, result, qd, qt)
    }

    /// Block until request represented by `qt` is finished returning the file descriptor
    /// representing this request and the results of that operation.
    pub fn wait2(&mut self, qt: QToken) -> (FileDescriptor, OperationResult<RT>) {
        #[cfg(feature = "profiler")]
        timer!("catnip::wait2");
        trace!("wait2(): qt={:?}", qt);
        let handle = self.rt.scheduler().from_raw_handle(qt).unwrap();

        // Continously call the scheduler to make progress until the future represented by `qt`
        // finishes.
        loop {
            self.poll_bg_work();
            if handle.has_completed() {
                return self.take_operation(handle);
            }
        }
    }

    pub fn wait_all_pushes(&mut self, qts: &mut Vec<QToken>) {
        #[cfg(feature = "profiler")]
        timer!("catnip::wait_all_pushes");
        trace!("wait_all_pushes(): qts={:?}", qts);
        self.poll_bg_work();
        for qt in qts.drain(..) {
            let handle = self.rt.scheduler().from_raw_handle(qt).unwrap();
            // TODO I don't understand what guarantees that this task will be done by the time we
            // get here and make this assert true.
            assert!(handle.has_completed());
            must_let!(let (_, OperationResult::Push) = self.take_operation(handle));
        }
    }

    /// Given a list of queue tokens, run all ready tasks and return the first task which has
    /// finished.
    pub fn wait_any(&mut self, qts: &[QToken]) -> (usize, dmtr_qresult_t) {
        #[cfg(feature = "profiler")]
        timer!("catnip::wait_any");
        trace!("wait_any(): qts={:?}", qts);
        loop {
            self.poll_bg_work();
            for (i, &qt) in qts.iter().enumerate() {
                let handle = self.rt.scheduler().from_raw_handle(qt).unwrap();
                if handle.has_completed() {
                    let (qd, r) = self.take_operation(handle);
                    return (i, dmtr_qresult_t::pack(&self.rt, r, qd, qt));
                }
                handle.into_raw();
            }
        }
    }

    pub fn wait_any2(&mut self, qts: &[QToken]) -> (usize, FileDescriptor, OperationResult<RT>) {
        #[cfg(feature = "profiler")]
        timer!("catnip::wait_any2");
        trace!("wait_any2(): qts={:?}", qts);
        loop {
            self.poll_bg_work();
            for (i, &qt) in qts.iter().enumerate() {
                let handle = self.rt.scheduler().from_raw_handle(qt).unwrap();
                if handle.has_completed() {
                    let (qd, r) = self.take_operation(handle);
                    return (i, qd, r);
                }
                handle.into_raw();
            }
        }
    }

    pub fn is_qd_valid(&self, _fd: FileDescriptor) -> bool {
        true
    }

    /// Given a handle representing a task in our scheduler. Return the results of this future
    /// and the file descriptor for this connection.
    ///
    /// This function will panic if the specified future had not completed or is _background_ future.
    fn take_operation(&mut self, handle: SchedulerHandle) -> (FileDescriptor, OperationResult<RT>) {
        match self.rt.scheduler().take(handle) {
            Operation::Tcp(f) => f.expect_result(),
            Operation::Udp(f) => f.expect_result(),
            Operation::Background(..) => panic!("`take_operation` attempted on background task!"),
        }
    }

    /// Scheduler will poll all futures that are ready to make progress.
    /// Then ask the runtime to receive new data which we will forward to the engine to parse and
    /// route to the correct protocol.
    fn poll_bg_work(&mut self) {
        #[cfg(feature = "profiler")]
        timer!("catnip::poll_bg_work");
        {
            #[cfg(feature = "profiler")]
            timer!("catnip::poll_bg_work::poll");
            self.rt.scheduler().poll();
        }

        {
            #[cfg(feature = "profiler")]
            timer!("catnip::poll_bg_work::for");

            for _ in 0..MAX_RECV_ITERS {
                let batch = {
                    #[cfg(feature = "profiler")]
                    timer!("catnip::poll_bg_work::for::receive");

                    self.rt.receive()
                };

                {
                    #[cfg(feature = "profiler")]
                    timer!("catnip::poll_bg_work::for::for");

                    if batch.is_empty() {
                        break;
                    }

                    for pkt in batch {
                        if let Err(e) = self.engine.receive(pkt) {
                            warn!("Dropped packet: {:?}", e);
                        }
                    }
                }
            }
        }

        if self.ts_iters == 0 {
            self.rt.advance_clock(Instant::now());
        }
        self.ts_iters = (self.ts_iters + 1) % TIMER_RESOLUTION;
    }
}
