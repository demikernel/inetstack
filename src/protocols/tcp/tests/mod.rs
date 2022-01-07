// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod established;
pub mod setup;

use std::{net::Ipv4Addr, num::Wrapping};

use crate::{
    collections::bytes::Bytes,
    protocols::{
        ethernet2::{EtherType2, Ethernet2Header, MacAddress},
        ipv4::Ipv4Header,
        tcp::segment::TcpHeader,
    },
};

//=============================================================================

/// Checks for a data packet.
pub fn check_packet_data(
    bytes: Bytes,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    window_size: u16,
    seq_num: Wrapping<u32>,
    ack_num: Option<Wrapping<u32>>,
) -> usize {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    assert_eq!(eth2_header.src_addr, eth2_src_addr);
    assert_eq!(eth2_header.dst_addr, eth2_dst_addr);
    assert_eq!(eth2_header.ether_type, EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    assert_eq!(ipv4_header.src_addr, ipv4_src_addr);
    assert_eq!(ipv4_header.dst_addr, ipv4_dst_addr);
    let (tcp_header, tcp_payload) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    assert_ne!(tcp_payload.len(), 0);
    assert_eq!(tcp_header.window_size, window_size);
    assert_eq!(tcp_header.seq_num, seq_num);
    if let Some(ack_num) = ack_num {
        assert_eq!(tcp_header.ack, true);
        assert_eq!(tcp_header.ack_num, ack_num);
    }

    tcp_payload.len()
}

//=============================================================================

/// Checks for a pure ACL packet.
pub fn check_packet_pure_ack(
    bytes: Bytes,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    window_size: u16,
    ack_num: Wrapping<u32>,
) {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    assert_eq!(eth2_header.src_addr, eth2_src_addr);
    assert_eq!(eth2_header.dst_addr, eth2_dst_addr);
    assert_eq!(eth2_header.ether_type, EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    assert_eq!(ipv4_header.src_addr, ipv4_src_addr);
    assert_eq!(ipv4_header.dst_addr, ipv4_dst_addr);
    let (tcp_header, tcp_payload) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    assert_eq!(tcp_payload.len(), 0);
    assert_eq!(tcp_header.window_size, window_size);
    assert_eq!(tcp_header.seq_num, Wrapping(0));
    assert_eq!(tcp_header.ack, true);
    assert_eq!(tcp_header.ack_num, ack_num);
}
