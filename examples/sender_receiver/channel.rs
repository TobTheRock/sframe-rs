use clap::Args;
use rand::{RngExt, rng};

/// What an [`UnreliableChannel`] did to a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transmission {
    /// Delivered as sent.
    Delivered,
    /// Lost on the way, the receiver never sees it.
    Dropped,
    /// Delivered twice, the receiver has to detect the replay.
    Duplicated,
    /// Held back, so it arrives after the packets sent in the meantime.
    Delayed,
}

/// Chance in percent for each of the disturbances an [`UnreliableChannel`] applies.
/// A packet is disturbed at most once, so the chances must not exceed 100% in total.
#[derive(Args, Debug, Clone, Copy)]
pub struct Disturbance {
    /// Percentage of packets which are lost on the way
    #[arg(long, default_value_t = 20)]
    pub drop: u8,
    /// Percentage of packets which are delivered twice
    #[arg(long, default_value_t = 20)]
    pub duplicate: u8,
    /// Percentage of packets which are held back and arrive late
    #[arg(long, default_value_t = 20)]
    pub delay: u8,
}

/// Models a lossy transport, e.g. UDP: packets may be dropped, duplicated or
/// arrive out of order.
pub struct UnreliableChannel {
    /// Held back packets, delivered with the next transmission.
    delayed: Vec<Vec<u8>>,
    disturbance: Disturbance,
}

impl UnreliableChannel {
    /// Creates a channel which disturbs the packets with the given chances.
    pub fn new(disturbance: Disturbance) -> Self {
        let Disturbance {
            drop,
            duplicate,
            delay,
        } = disturbance;
        assert!(
            drop as u32 + duplicate as u32 + delay as u32 <= 100,
            "The disturbances must not exceed 100% in total"
        );
        Self {
            delayed: Vec::new(),
            disturbance,
        }
    }

    /// Transmits a packet, returning what arrives on the other side and what
    /// happened to it. Packets held back earlier are appended, arriving late.
    pub fn transmit(&mut self, packet: &[u8]) -> (Transmission, Vec<Vec<u8>>) {
        // taken before this packet is queued, so a delayed one arrives after it
        let held_back = std::mem::take(&mut self.delayed);

        let Disturbance {
            drop,
            duplicate,
            delay,
        } = self.disturbance;

        let mut arriving = Vec::new();
        let transmission = match rng().random_range(0..100) {
            n if n < drop => Transmission::Dropped,
            n if n < drop + duplicate => {
                arriving.push(packet.to_vec());
                arriving.push(packet.to_vec());
                Transmission::Duplicated
            }
            n if n < drop + duplicate + delay => {
                self.delayed.push(packet.to_vec());
                Transmission::Delayed
            }
            _ => {
                arriving.push(packet.to_vec());
                Transmission::Delivered
            }
        };

        arriving.extend(held_back);
        (transmission, arriving)
    }
}
