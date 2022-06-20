// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//==============================================================================
// Imports
//==============================================================================

use ::runtime::{
    fail::Fail,
    memory::Buffer,
    QDesc,
};
use ::std::{
    fmt,
    net::SocketAddrV4,
};

//==============================================================================
// Structures
//==============================================================================

pub enum OperationResult {
    Connect,
    Accept(QDesc),
    Push,
    // TODO: Drop wrapping Option.
    Pop(Option<SocketAddrV4>, Buffer),
    Failed(Fail),
}

//==============================================================================
// Trait Implementations
//==============================================================================

impl fmt::Debug for OperationResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OperationResult::Connect => write!(f, "Connect"),
            OperationResult::Accept(..) => write!(f, "Accept"),
            OperationResult::Push => write!(f, "Push"),
            OperationResult::Pop(..) => write!(f, "Pop"),
            OperationResult::Failed(ref e) => write!(f, "Failed({:?})", e),
        }
    }
}
