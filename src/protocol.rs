pub mod icmp;
pub mod tcp;

pub use icmp::ICMP;

use crate::ip::{IPPacketError, IPPacketErrorKind};

pub enum IPBody {
    ICMP(ICMP),
}
impl IPBody {
    /// body_buf (The IP packet's body buffer of bytes starts at 0)
    pub fn from_byte_buffer(protocol: u8, body_buf: &[u8]) -> Result<Self, IPPacketError> {
        match protocol {
            1 => Ok(Self::ICMP(ICMP::from_byte_buffer(body_buf)?)),
            _ => Err(IPPacketError::new(IPPacketErrorKind::NotImplementedYet)),
        }
    }
    pub fn to_byte_buffer(&self) -> Vec<u8> {
        match self {
            Self::ICMP(icmp) => icmp.to_byte_buffer(),
            _ => panic!("Not implemented yet"),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::ICMP(icmp) => icmp.len(),
            _ => panic!("Not implemented yet"),
        }
    }
}
