use crate::checksum::ones_complement_sum_byte_buffer;
use crate::ip::{IPPacketError, IPPacketErrorKind};

#[derive(Debug, Clone)]
pub struct ICMP {
    pub _type: u8,
    pub code: u8,
    pub checksum: u16,
    pub body: ICMPBody,
}
impl ICMP {
    pub fn new(_type: u8, code: u8, body: ICMPBody) -> Self {
        let mut icmp = Self {
            _type,
            code,
            checksum: 0x0,
            body,
        };
        let checksum = !ones_complement_sum_byte_buffer(&icmp.to_byte_buffer());
        icmp.checksum = checksum;
        icmp
    }
    pub fn from_byte_buffer(buf: &[u8]) -> Result<Self, IPPacketError> {
        // Check checksum
        if ones_complement_sum_byte_buffer(buf) != 0xFFFF {
            return Err(IPPacketError::new(IPPacketErrorKind::ICMPChecksumError));
        }
        let _type = buf[0];
        let code = buf[1];
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        Ok(Self {
            _type,
            code,
            checksum,
            body: ICMPBody::from_byte_buffer(_type, &buf[4..]),
        })
    }
    pub fn to_byte_buffer(&self) -> Vec<u8> {
        let mut buf = vec![self._type, self.code];
        buf.append(&mut self.checksum.to_be_bytes().to_vec());
        buf.append(&mut self.body.to_byte_buffer());
        buf
    }
    pub fn len(&self) -> usize {
        4 + self.body.len()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ICMPBody {
    EchoReply {
        identifier: u16,
        sequence_number: u16,
        data: Vec<u8>,
    },
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    Echo {
        identifier: u16,
        sequence_number: u16,
        data: Vec<u8>,
    },
    TimeExceeded,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    InformationRequest,
    InformationReply,
}
impl ICMPBody {
    pub fn to_byte_buffer(&self) -> Vec<u8> {
        match self {
            Self::Echo {
                identifier,
                sequence_number,
                data,
            }
            | Self::EchoReply {
                identifier,
                sequence_number,
                data,
            } => {
                let mut buf = identifier.to_be_bytes().to_vec();
                buf.append(&mut sequence_number.to_be_bytes().to_vec());
                buf.append(&mut data.clone());
                buf
            }
            _ => panic!("Not implemented yet"),
        }
    }
    pub fn from_byte_buffer(_type: u8, body_buf: &[u8]) -> Self {
        match _type {
            0 => Self::EchoReply {
                identifier: u16::from_be_bytes([body_buf[0], body_buf[1]]),
                sequence_number: u16::from_be_bytes([body_buf[2], body_buf[3]]),
                data: body_buf[4..].to_vec(),
            },
            3 => Self::DestinationUnreachable,
            4 => Self::SourceQuench,
            5 => Self::Redirect,
            8 => Self::Echo {
                identifier: u16::from_be_bytes([body_buf[0], body_buf[1]]),
                sequence_number: u16::from_be_bytes([body_buf[2], body_buf[3]]),
                data: body_buf[4..].to_vec(),
            },
            11 => Self::TimeExceeded,
            12 => Self::ParameterProblem,
            13 => Self::Timestamp,
            14 => Self::TimestampReply,
            15 => Self::InformationRequest,
            16 => Self::InformationReply,
            _ => panic!("ICMP should not be able to have this type"),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Echo {
                identifier: _,
                sequence_number: _,
                data,
            }
            | Self::EchoReply {
                identifier: _,
                sequence_number: _,
                data,
            } => 4 + data.len(), // 4 bytes from identifier and sequence_number
            _ => panic!("Not implemented yet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_from_byte_buffer() {
        let buf: [u8; 64] = [
            0x8, 0x0, 0xc0, 0x66, 0x0, 0xf, 0x0, 0x1, 0xa2, 0xaa, 0xd3, 0x67, 0x0, 0x0, 0x0, 0x0,
            0xf7, 0xa3, 0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37,
        ];
        let icmp = ICMP::from_byte_buffer(&buf).unwrap();
    }

    #[test]
    fn icmp_new() {
        let icmp_body = ICMPBody::EchoReply {
            identifier: 0xf,
            sequence_number: 0x1,
            data: vec![
                0xa2, 0xaa, 0xd3, 0x67, 0x0, 0x0, 0x0, 0x0, 0xf7, 0xa3, 0xb, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
                0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            ],
        };
        let icmp = ICMP::new(0x0, 0x0, icmp_body);
        assert_eq!(icmp.checksum, 0xc866);
    }

    mod icmp_body_tests {
        use crate::protocol::icmp::ICMPBody;

        #[test]
        fn from_byte_buffer_echo() {
            let _type = 8u8;
            let buf: [u8; 60] = [
                0x0, 0xf, 0x0, 0x1, 0xa2, 0xaa, 0xd3, 0x67, 0x0, 0x0, 0x0, 0x0, 0xf7, 0xa3, 0xb,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
                0x35, 0x36, 0x37,
            ];
            let icmp_body = ICMPBody::from_byte_buffer(_type, &buf);
            assert_eq!(
                icmp_body,
                ICMPBody::Echo {
                    identifier: 0xf,
                    sequence_number: 0x1,
                    data: [
                        0xa2, 0xaa, 0xd3, 0x67, 0x0, 0x0, 0x0, 0x0, 0xf7, 0xa3, 0xb, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                        0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                        0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
                        0x33, 0x34, 0x35, 0x36, 0x37,
                    ]
                    .to_vec()
                }
            )
        }
    }
}
