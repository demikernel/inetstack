// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{
    CongestionControl, FastRetransmitRecovery, LimitedTransmit, Options,
    SlowStartCongestionAvoidance,
};
use crate::{protocols::tcp::SeqNumber, runtime::Runtime};
use std::fmt::Debug;

// Implementation of congestion control which does nothing.
#[derive(Debug)]
pub struct None {}

impl<RT: Runtime> CongestionControl<RT> for None {
    fn new(
        _mss: usize,
        _seq_no: SeqNumber,
        _options: Option<Options>,
    ) -> Box<dyn CongestionControl<RT>> {
        Box::new(Self {})
    }
}

impl<RT: Runtime> SlowStartCongestionAvoidance<RT> for None {}
impl<RT: Runtime> FastRetransmitRecovery<RT> for None {}
impl<RT: Runtime> LimitedTransmit<RT> for None {}
