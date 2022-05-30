// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::protocols::tcp::SeqNumber;
#[allow(unused_imports)]
use std::{
    hash::Hasher,
    net::SocketAddrV4,
    num::Wrapping,
};

#[allow(dead_code)]
pub struct IsnGenerator {
    nonce: u32,
    counter: Wrapping<u16>,
}

impl IsnGenerator {
    pub fn new(nonce: u32) -> Self {
        Self {
            nonce,
            counter: Wrapping(0),
        }
    }

    #[cfg(test)]
    pub fn generate(&mut self, _local: &SocketAddrV4, _remote: &SocketAddrV4) -> SeqNumber {
        SeqNumber::from(0)
    }

    #[cfg(not(test))]
    pub fn generate(&mut self, local: &SocketAddrV4, remote: &SocketAddrV4) -> SeqNumber {
        let crc: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);
        let mut digest = crc.digest();
        let remote_addr: u32 = u32::from_be_bytes(remote.ip().octets());
        digest.update(&remote_addr.to_be_bytes());
        let remote_port: u16 = remote.port().into();
        digest.update(&remote_port.to_be_bytes());
        let local_addr: u32 = u32::from_be_bytes(local.ip().octets());
        digest.update(&local_addr.to_be_bytes());
        let local_port: u16 = local.port().into();
        digest.update(&local_port.to_be_bytes());
        digest.update(&self.nonce.to_be_bytes());
        let digest = digest.finalize();
        let isn = SeqNumber::from(digest + self.counter.0 as u32);
        self.counter += Wrapping(1);
        isn
    }
}
