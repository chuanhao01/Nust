use std::io;

use nust::{
    ip::IPHeader,
    protocol::{ICMPBody, IPBody, TCPControlBits, ICMP, TCP},
    IPPacket,
};
use tun_tap::{Iface, Mode};

const INTERFACE_NAME: &str = "tun0";

fn main() -> io::Result<()> {
    let iface = Iface::new(INTERFACE_NAME, Mode::Tun)?;
    let mut buf = vec![0u8; 1504]; // MTU + 4 for the header
    loop {
        let bytes_copied_to_buffer = iface.recv(&mut buf)?; // Wait until a packet arrives
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if protocol == 0x0800 {
            println!("Front 4 bytes: {:x?}", &buf[..4]);
            if let Ok(ip_packet) = IPPacket::from_byte_buffer(&buf[4..bytes_copied_to_buffer]) {
                println!("{:#x}", ip_packet.header.protocol);
                let header = ip_packet.header;
                let body = ip_packet.body;
                #[allow(clippy::single_match)]
                let reply_ip_packet = match &body {
                    IPBody::ICMP(icmp) => match &icmp.body {
                        ICMPBody::Echo {
                            identifier: _,
                            sequence_number: _,
                            data: _,
                        } => {
                            let ip_body =
                                IPBody::ICMP(ICMP::new(0x0, icmp.code, icmp.body.clone()));
                            let ip_header = IPHeader::from_body(
                                header.version,
                                header.type_of_service,
                                header.identification,
                                header.flags,
                                header.fragment_offset,
                                header.time_to_live,
                                header.protocol,
                                header.destination_addr,
                                header.source_addr,
                                header.options,
                                ip_body.len() as u16,
                            );
                            Some(IPPacket::new(ip_header, ip_body))
                        }
                        _ => None,
                    },
                    IPBody::TCP(tcp) => match &tcp.control_bits {
                        // SYN
                        0b10 => {
                            // Need to SYN ACK the request
                            let ip_body = IPBody::TCP(TCP::new(
                                &header.destination_addr,
                                &header.source_addr,
                                header.protocol,
                                tcp.destination_port,
                                tcp.source_port,
                                0,
                                tcp.sequence_number + 1,
                                0,
                                TCPControlBits::SYN.to_u8() + TCPControlBits::ACK.to_u8(),
                                tcp.window,
                                0,
                                tcp.options.clone(),
                                Vec::new(),
                            ));
                            let ip_header = IPHeader::from_body(
                                header.version,
                                header.type_of_service,
                                header.identification,
                                header.flags,
                                header.fragment_offset,
                                header.time_to_live,
                                header.protocol,
                                header.destination_addr,
                                header.source_addr,
                                header.options,
                                ip_body.len() as u16,
                            );
                            Some(IPPacket::new(ip_header, ip_body))
                        }
                        _ => {
                            // Not implemented yet, so ignore the request
                            None
                        }
                    },
                    _ => {
                        // Ignore anything we don't want to handle
                        None
                    }
                };
                if let Some(reply_ip_packet) = reply_ip_packet {
                    let mut res_buf: Vec<u8> = vec![0x0, 0x0, 0x8, 0x0];
                    res_buf.append(&mut reply_ip_packet.to_byte_buffer());
                    println!("original: {:x?}", &buf[4..]);
                    println!("reply: {:x?}", res_buf);
                    iface.send(&res_buf)?;
                }
            };
        } else {
            println!("Not a ipv4 packet to parse")
        }
    }
}
