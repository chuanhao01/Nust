pub mod icmp;
pub mod tcp;

pub use icmp::{ICMPBody, ICMP};
pub use tcp::{TCPControlBits, TCP};

use crate::ip::{IPHeader, IPPacketError, IPPacketErrorKind};

pub enum IPBody {
    ICMP(ICMP),
    TCP(TCP),
}
impl IPBody {
    /// body_buf (The IP packet's body buffer of bytes starts at 0)
    pub fn from_byte_buffer(ip_header: &IPHeader, body_buf: &[u8]) -> Result<Self, IPPacketError> {
        match ip_header.protocol {
            1 => Ok(Self::ICMP(ICMP::from_byte_buffer(body_buf)?)),
            6 => Ok(Self::TCP(TCP::from_byte_buffer(
                body_buf,
                &ip_header.source_addr,
                &ip_header.destination_addr,
                ip_header.protocol,
            )?)),
            _ => Err(IPPacketError::new(IPPacketErrorKind::NotImplementedYet)),
        }
    }
    pub fn to_byte_buffer(&self) -> Vec<u8> {
        match self {
            Self::ICMP(icmp) => icmp.to_byte_buffer(),
            Self::TCP(tcp) => tcp.to_byte_buffer(),
            _ => panic!("Not implemented yet"),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::ICMP(icmp) => icmp.len(),
            Self::TCP(tcp) => tcp.len(),
            _ => panic!("Not implemented yet"),
        }
    }
}
