use std::net::Ipv4Addr;

pub struct IPPacket {
    pub header: IPHeader,
}

impl IPPacket {
    pub fn new(buf: &[u8]) -> Self {
        let ihl = IPHeader::get_ihl(buf[0]);
        Self {
            header: IPHeader::new(&buf[..(ihl * 4) as usize]),
        }
    }
}

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
    pub header_checksum: u16,
    pub source_addr: Ipv4Addr,
    pub destination_addr: Ipv4Addr,
    pub options: Option<Vec<u8>>,
}

impl IPHeader {
    pub fn new(buf: &[u8]) -> Self {
        let ihl = Self::get_ihl(buf[0]);
        let options = if ihl == 5 {
            None
        } else {
            Some(buf[20..].to_vec())
        };
        Self {
            version: Self::get_version(buf[0]),
            ihl,
            type_of_service: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags: Self::get_flag(buf[6]),
            fragment_offset: Self::get_fragment_offset([buf[6], buf[7]]),
            time_to_live: buf[8],
            protocol: buf[9],
            header_checksum: u16::from_be_bytes([buf[10], buf[11]]),
            source_addr: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            destination_addr: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            options,
        }
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
