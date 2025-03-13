use std::net::Ipv4Addr;

use crate::checksum;

pub struct IPPacket {
    pub header: IPHeader,
}
impl IPPacket {
    pub fn new(buf: &[u8]) -> Result<Self, IPPacketError> {
        let ihl = IPHeader::get_ihl(buf[0]);
        Ok(Self {
            header: IPHeader::from_byte_buffer(&buf[..(ihl * 4) as usize])?,
        })
    }
}
#[derive(Debug)]
pub struct IPPacketError {
    kind: IPPacketErrorKind,
}
impl IPPacketError {
    pub fn new(kind: IPPacketErrorKind) -> Self {
        Self { kind }
    }
}
#[derive(Debug)]
pub enum IPPacketErrorKind {
    IPHeaderChecksumError,
    IPICMPError,
}

#[derive(Debug)]
pub struct IPHeader {
    pub version: u8, // 4 bits
    // Internet Header Length
    pub ihl: u8, // 4 bits
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,            // 3 bits
    pub fragment_offset: u16, // 13 bits
    pub time_to_live: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_addr: Ipv4Addr,
    pub destination_addr: Ipv4Addr,
    pub options: Option<Vec<u8>>,
}
impl IPHeader {
    /// To create a new IPHeader given fields, calculates and sets the checksum for you
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8, // 4 bits
        ihl: u8,     // 4 bits
        type_of_service: u8,
        total_length: u16,
        identification: u16,
        flags: u8,            // 3 bits
        fragment_offset: u16, // 13 bits
        time_to_live: u8,
        protocol: u8,
        source_addr: Ipv4Addr,
        destination_addr: Ipv4Addr,
        options: Option<Vec<u8>>,
    ) -> Self {
        let mut ip_header = Self {
            version,
            ihl,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            time_to_live,
            protocol,
            checksum: 0x0,
            source_addr,
            destination_addr,
            options,
        };
        let header_checksum =
            !checksum::ones_complement_sum_byte_buffer(&ip_header.to_byte_buffer()); // Taking the one's complement
        ip_header.checksum = header_checksum;
        ip_header
    }
    /// Parsing from raw bytes buffer
    pub fn from_byte_buffer(buf: &[u8]) -> Result<Self, IPPacketError> {
        let ihl = Self::get_ihl(buf[0]);
        let options = if ihl == 5 {
            None
        } else {
            Some(buf[20..].to_vec())
        };
        if checksum::ones_complement_sum_byte_buffer(buf) != 0xFFFF {
            return Err(IPPacketError::new(IPPacketErrorKind::IPHeaderChecksumError));
        }
        Ok(Self {
            version: Self::get_version(buf[0]),
            ihl,
            type_of_service: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags: Self::get_flag(buf[6]),
            fragment_offset: Self::get_fragment_offset([buf[6], buf[7]]),
            time_to_live: buf[8],
            protocol: buf[9],
            checksum: u16::from_be_bytes([buf[10], buf[11]]),
            source_addr: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            destination_addr: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            options,
        })
    }
    /// Creates the byte buffer using the values in the header
    fn to_byte_buffer(&self) -> Vec<u8> {
        let mut buf = [((self.version << 4) + self.ihl), self.type_of_service].to_vec();
        buf.append(&mut self.total_length.to_be_bytes().to_vec());
        buf.append(&mut self.identification.to_be_bytes().to_vec());
        buf.push((self.flags << 5) + (self.fragment_offset >> 8) as u8);
        buf.push((self.fragment_offset & 0xFF) as u8);
        buf.push(self.time_to_live);
        buf.push(self.protocol);
        buf.append(&mut self.checksum.to_be_bytes().to_vec());
        buf.append(&mut self.source_addr.to_bits().to_be_bytes().to_vec());
        buf.append(&mut self.destination_addr.to_bits().to_be_bytes().to_vec());
        if let Some(options) = &self.options {
            buf.append(&mut options.clone());
        }
        buf
    }

    fn get_version(x: u8) -> u8 {
        // Extracts from the first byte
        x >> 4
    }
    fn get_ihl(x: u8) -> u8 {
        // Extract from first byte
        x & 0b00001111
    }
    fn get_flag(x: u8) -> u8 {
        x >> 5
    }
    fn get_fragment_offset(x: [u8; 2]) -> u16 {
        let mut x = x;
        x[0] &= 0b00011111;
        u16::from_be_bytes(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod ipheader_tests {
        use super::*;
        #[test]
        fn from_correct_ping_packet_fields() {
            let buf: [u8; 20] = [
                0x45, 0x0, 0x0, 0x54, 0x1b, 0xb, 0x40, 0x0, 0x40, 0x1, 0x9e, 0x4a, 0xc0, 0xa8, 0x0,
                0x1, 0xc0, 0xa8, 0x0, 0x2,
            ];
            let ip_header = IPHeader::from_byte_buffer(&buf).unwrap();
            assert_eq!(ip_header.version, 0x4);
            assert_eq!(ip_header.ihl, 0x5);
            assert_eq!(ip_header.type_of_service, 0x0);
            assert_eq!(ip_header.total_length, 0x54);
            assert_eq!(ip_header.identification, 0x1b0b);
            assert_eq!(ip_header.flags, 0b010);
            assert_eq!(ip_header.fragment_offset, 0x0);
            assert_eq!(ip_header.time_to_live, 0x40);
            assert_eq!(ip_header.protocol, 0x1);
            assert_eq!(ip_header.checksum, 0x9e4a);
            assert_eq!(ip_header.source_addr, Ipv4Addr::from_bits(0xc0a80001));
            assert_eq!(ip_header.destination_addr, Ipv4Addr::from_bits(0xc0a80002));
            assert!(ip_header.options.is_none());
            let ip_header_buf = ip_header.to_byte_buffer();
            assert_eq!(ip_header_buf, buf);
            let new_ip_header = IPHeader::new(
                ip_header.version,
                ip_header.ihl,
                ip_header.type_of_service,
                ip_header.total_length,
                ip_header.identification,
                ip_header.flags,
                ip_header.fragment_offset,
                ip_header.time_to_live,
                ip_header.protocol,
                ip_header.source_addr,
                ip_header.destination_addr,
                ip_header.options,
            );
            assert_eq!(new_ip_header.checksum, ip_header.checksum);
        }
    }
}
