use std::io;

use nust::IPPacket;
use tun_tap::{Iface, Mode};

const INTERFACE_NAME: &str = "tun0";

fn main() -> io::Result<()> {
    let iface = Iface::new(INTERFACE_NAME, Mode::Tun)?;
    let mut buf = vec![0u8; 1504]; // MTU + 4 for the header
    loop {
        let bytes_copied_to_buffer = iface.recv(&mut buf)?; // Wait until a packet arrives
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if protocol == 0x0800 {
            if let Ok(ip_packet) = IPPacket::new(&buf[4..bytes_copied_to_buffer]) {
                println!("{:x?}", ip_packet.header.protocol);
            };
        } else {
            println!("Not a ipv4 packet to parse")
        }
    }
}
