// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    protocols::tcp::{
        constants::{DEFAULT_MSS, MAX_MSS, MIN_MSS},
        established::cc::{self, CongestionControl, CongestionControlConstructor},
    },
    runtime::Runtime,
};
use std::time::Duration;

/// Options for TCP Stack
#[derive(Clone, Debug)]
pub struct TcpOptions<RT: Runtime> {
    /// Maximum Segment Size
    advertised_mss: usize,
    /// Congestion Control Type
    congestion_ctrl_type: CongestionControlConstructor<RT>,
    /// Options for Congestion Control Algorithm
    congestion_ctrl_options: Option<cc::Options>,
    /// Number of Retries for TCP Handshake Algorithm
    handshake_retries: usize,
    /// Timeout for TCP Handshake Algorithm
    handshake_timeout: Duration,
    /// Window Size
    receive_window_size: u16,
    /// Scaling Factor for Window Size
    window_scale: u8,
    /// Timeout for Delayed ACKs
    ack_delay_timeout: Duration,
    /// Offload Checksum to Hardware on Receiving Peer?
    rx_checksum_offload: bool,
    /// Offload Checksum to Hardware on Sending Peer?
    tx_checksum_offload: bool,
}

impl<RT: Runtime> Default for TcpOptions<RT> {
    fn default() -> Self {
        TcpOptions {
            advertised_mss: DEFAULT_MSS,
            congestion_ctrl_type: cc::None::new,
            congestion_ctrl_options: None,
            handshake_retries: 5,
            handshake_timeout: Duration::from_secs(3),
            receive_window_size: 0xffff,
            ack_delay_timeout: Duration::from_millis(5),
            window_scale: 0,
            rx_checksum_offload: false,
            tx_checksum_offload: false,
        }
    }
}

impl<RT: Runtime> TcpOptions<RT> {
    pub fn new(
        advertised_mss: Option<usize>,
        congestion_ctrl_type: Option<CongestionControlConstructor<RT>>,
        congestion_ctrl_options: Option<cc::Options>,
        handshake_retries: Option<usize>,
        handshake_timeout: Option<Duration>,
        receive_window_size: Option<u16>,
        window_scale: Option<u8>,
        ack_delay_timeout: Option<Duration>,
        rx_checksum_offload: Option<bool>,
        tx_checksum_offload: Option<bool>,
    ) -> Self {
        let mut options = Self::default();

        if let Some(value) = advertised_mss {
            options = options.set_advertised_mss(value);
        }
        if let Some(value) = congestion_ctrl_type {
            options = options.set_congestion_ctrl_type(value);
        }
        if let Some(value) = congestion_ctrl_options {
            options = options.set_congestion_ctrl_options(value);
        }
        if let Some(value) = handshake_retries {
            options = options.set_handshake_retries(value);
        }
        if let Some(value) = handshake_timeout {
            options = options.set_handshake_timeout(value);
        }
        if let Some(value) = receive_window_size {
            options = options.set_receive_window_size(value);
        }
        if let Some(value) = window_scale {
            options = options.set_window_scale(value);
        }
        if let Some(value) = ack_delay_timeout {
            options = options.set_ack_delay_timeout(value);
        }
        if let Some(value) = rx_checksum_offload {
            options.rx_checksum_offload = value;
        }
        if let Some(value) = tx_checksum_offload {
            options.tx_checksum_offload = value;
        }

        options
    }

    pub fn advertised_mss(&self) -> usize {
        self.advertised_mss
    }

    pub fn congestion_ctrl_type(&self) -> CongestionControlConstructor<RT> {
        self.congestion_ctrl_type
    }

    pub fn congestion_ctrl_options(&self) -> Option<cc::Options> {
        self.congestion_ctrl_options.clone()
    }

    pub fn handshake_retries(&self) -> usize {
        self.handshake_retries
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn receive_window_size(&self) -> u16 {
        self.receive_window_size
    }

    pub fn window_scale(&self) -> u8 {
        self.window_scale
    }

    pub fn tx_checksum_offload(&self) -> bool {
        self.tx_checksum_offload
    }

    pub fn rx_checksum_offload(&self) -> bool {
        self.rx_checksum_offload
    }

    pub fn ack_delay_timeout(&self) -> Duration {
        self.ack_delay_timeout
    }

    fn set_advertised_mss(mut self, value: usize) -> Self {
        assert!(value >= MIN_MSS);
        assert!(value <= MAX_MSS);
        self.advertised_mss = value;
        self
    }

    fn set_congestion_ctrl_type(mut self, value: CongestionControlConstructor<RT>) -> Self {
        self.congestion_ctrl_type = value;
        self
    }

    fn set_congestion_ctrl_options(mut self, value: cc::Options) -> Self {
        self.congestion_ctrl_options = Some(value);
        self
    }

    fn set_handshake_retries(mut self, value: usize) -> Self {
        assert!(value > 0);
        self.handshake_retries = value;
        self
    }

    fn set_handshake_timeout(mut self, value: Duration) -> Self {
        assert!(value > Duration::new(0, 0));
        self.handshake_timeout = value;
        self
    }

    fn set_receive_window_size(mut self, value: u16) -> Self {
        assert!(value > 0);
        self.receive_window_size = value;
        self
    }

    fn set_ack_delay_timeout(mut self, value: Duration) -> Self {
        assert!(value <= Duration::from_millis(500));
        self.ack_delay_timeout = value;
        self
    }

    fn set_window_scale(mut self, value: u8) -> Self {
        self.window_scale = value;
        self
    }
}
