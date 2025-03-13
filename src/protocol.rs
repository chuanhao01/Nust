pub mod icmp;

pub use icmp::ICMP;

pub enum Protocol {
    ICMP(ICMP),
}
