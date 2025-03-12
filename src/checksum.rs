/// Calculates the u16 one's complement sum of the entire buffer
/// Padding odd length byte with u8 0x0 to the right
pub fn ones_complement_sum_byte_buffer(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    assert!(!buf.is_empty()); // Should panic if buffer passed in is empty, might change in the future

    for chunk in buf.chunks(2) {
        let num = match chunk {
            [left, right] => u16::from_be_bytes([*left, *right]),
            [left] => u16::from_be_bytes([*left, 0]),
            _ => panic!("Should only have chunks of 1/2"),
        };
        sum += num as u32
    }
    // Fold the sum, 0xFF = u8
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 // one's complement sum
}

#[cfg(test)]
mod tests {
    use super::*;

    mod ones_complement_sum_byte_buffer_tests {
        use super::*;
        #[test]
        fn single_carry_over() {
            let buf: [u8; 4] = [0x80, 0x0, 0x80, 0x0];
            assert_eq!(0x1, ones_complement_sum_byte_buffer(&buf));
        }
        #[test]
        fn double_carry_over() {
            let buf: [u8; 6] = [0x80, 0x0, 0x80, 0x0, 0xFF, 0xFF];
            assert_eq!(0x1, ones_complement_sum_byte_buffer(&buf));
        }
    }
}
