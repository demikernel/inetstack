// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod active_open;
pub mod constants;
mod established;
mod isn_generator;
pub mod operations;
mod options;
mod passive_open;
pub mod peer;
pub mod segment;
mod sequence_number;

#[cfg(test)]
mod tests;

use std::num::Wrapping;

pub type SeqNumber = Wrapping<u32>;

pub use self::{established::cc, options::TcpOptions as Options, peer::Peer};
