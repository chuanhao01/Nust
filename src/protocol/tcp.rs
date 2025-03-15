use std::net::Ipv4Addr;

use crate::checksum;
use crate::ip::{IPPacketError, IPPacketErrorKind};

pub struct TCP {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,  // 4 bits
    reserved: u8,     // 6 bits
    control_bits: u8, // 6 bits
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: Option<Vec<u8>>,
    data: Vec<u8>,
}
impl TCP {
    pub fn to_byte_buffer(&self) -> Vec<u8> {
        let mut buf = self.source_port.to_be_bytes().to_vec();
        buf.append(&mut self.destination_port.to_be_bytes().to_vec());
        buf.append(&mut self.sequence_number.to_be_bytes().to_vec());
        buf.append(&mut self.acknowledgment_number.to_be_bytes().to_vec());
        buf.push((self.data_offset << 4) + (self.reserved >> 2));
        buf.push((self.reserved << 6) + self.control_bits);
        buf.append(&mut self.window.to_be_bytes().to_vec());
        buf.append(&mut self.checksum.to_be_bytes().to_vec());
        buf.append(&mut self.urgent_pointer.to_be_bytes().to_vec());
        if let Some(options) = &self.options {
            buf.append(&mut options.clone());
            if options.len() % 4 != 0 {
                // Pad options with 0
                buf.append(&mut vec![0u8; 4 - (options.len() % 4)]);
            }
        }
        buf.append(&mut self.data.clone());
        buf
    }
    pub fn from_byte_buffer(
        buf: &[u8],
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        protocol: u8,
        ihl: u8, // IP Header Length
    ) -> Result<TCP, IPPacketError> {
        let mut pseudo_header = source_address.to_bits().to_be_bytes().to_vec();
        pseudo_header.append(&mut destination_address.to_bits().to_be_bytes().to_vec());
        pseudo_header.push(0x0);
        pseudo_header.push(protocol);
        pseudo_header.append(&mut (buf.len() as u16).to_be_bytes().to_vec());
        pseudo_header.append(&mut buf.to_vec());
        if checksum::ones_complement_sum_byte_buffer(&pseudo_header) != 0xFFFF {
            return Err(IPPacketError::new(IPPacketErrorKind::TCPChecksumError));
        }
        let data_reserved_control_seg = u16::from_be_bytes([buf[12], buf[13]]);
        let data_offset = (data_reserved_control_seg >> 12) as u8;
        let options = if data_offset - ihl == 5 {
            // No options
            None
        } else {
            Some(buf[20..(data_offset - ihl) as usize * 4].to_vec())
        };
        Ok(Self {
            source_port: u16::from_be_bytes([buf[0], buf[1]]),
            destination_port: u16::from_be_bytes([buf[2], buf[3]]),
            sequence_number: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            acknowledgment_number: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            data_offset,
            reserved: ((data_reserved_control_seg & 0xFFF) >> 6) as u8,
            control_bits: (data_reserved_control_seg & 0x3F) as u8,
            window: u16::from_be_bytes([buf[14], buf[15]]),
            checksum: u16::from_be_bytes([buf[16], buf[17]]),
            urgent_pointer: u16::from_be_bytes([buf[18], buf[19]]),
            options,
            data: buf[(data_offset - ihl) as usize * 4..].to_vec(),
        })
    }
}

pub enum TCPControlBits {
    URG,
    ACK,
    PSH,
    RST,
    SYN,
    FIN,
}
impl TCPControlBits {
    pub fn from_u8(control_bit: u8) -> Self {
        match control_bit {
            0b100000 => Self::URG,
            0b10000 => Self::ACK,
            0b1000 => Self::PSH,
            0b100 => Self::RST,
            0b10 => Self::SYN,
            0b1 => Self::FIN,
            _ => panic!("Corrupted TCP ControlBit Packet"),
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::URG => 0b100000,
            Self::ACK => 0b10000,
            Self::PSH => 0b1000,
            Self::RST => 0b100,
            Self::SYN => 0b10,
            Self::FIN => 0b1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte_buffer_checksum() {
        let buf: [u8; 40] = [
            0xbd, 0x4a, 0x0, 0x50, 0x84, 0x78, 0x87, 0x58, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0xfa,
            0xf0, 0xce, 0x13, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x4, 0x2, 0x8, 0xa, 0x82, 0x7a, 0xb1,
            0xc1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x7,
        ];
        let source_address = Ipv4Addr::new(192, 168, 0, 1);
        let destination_address = Ipv4Addr::new(192, 168, 0, 2);
        let protocol = 6;
        let tcp =
            TCP::from_byte_buffer(&buf, source_address, destination_address, protocol, 5).unwrap();
        assert!(tcp.options.is_none());
        assert_eq!(buf.to_vec(), tcp.to_byte_buffer());
    }
}
