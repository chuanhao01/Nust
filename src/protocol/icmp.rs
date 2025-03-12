pub struct ICMP {
    _type: ICMPType,
    code: u8,
    checksum: u8,
    identifier: Option<u16>,
    sequence_number: Option<u16>,
    originate_timestamp: Option<u32>,
    receive_timestamp: Option<u32>,
    transmit_timestamp: Option<u32>,
    data: Option<Vec<u8>>,
    gateway_internet_address: Option<u32>,
    internet_header_and_data: Option<u32>,
    pointer: Option<u8>,
}
impl ICMP {
    // pub fn from_byte_buffer()
}

pub enum ICMPType {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    Echo,
    TimeExceeded,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    InformationRequest,
    InformationReply,
}
impl ICMPType {
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::EchoReply => 0,
            Self::DestinationUnreachable => 3,
            Self::SourceQuench => 4,
            Self::Redirect => 5,
            Self::Echo => 8,
            Self::TimeExceeded => 11,
            Self::ParameterProblem => 12,
            Self::Timestamp => 13,
            Self::TimestampReply => 14,
            Self::InformationRequest => 15,
            Self::InformationReply => 15,
        }
    }
}
