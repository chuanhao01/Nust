use nust::checksum::ones_complement_sum_byte_buffer;

fn main() {
    let a = 0b01100010;
    // let a = 0x45;
    let b = a >> 5;
    println!("a: {:#010b}", a);
    println!("a: {}", a);
    println!("b: {:#010b}", b);
    println!("b: {}", b);

    println!("{:b}", 3u8);

    let buf = [4u8, 3u8, 2u8];
    for chunk in buf.chunks(2) {
        println!("{:?}", chunk)
    }

    let mut sum: u32 = 0x0001FFFF;
    println!("first {:#032b}", sum);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
        println!("{:#010b}", sum);
    }

    let buf = [
        0xc0, 0xa8, 0x0, 0x1, 0xc0, 0xa8, 0x0, 0x2, 0x0, 0x6, 0x0, 40u8, 0xbd, 0x4a, 0x0, 0x50,
        0x84, 0x78, 0x87, 0x58, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0xfa, 0xf0, 0xce, 0x13, 0x0, 0x0,
        0x2, 0x4, 0x5, 0xb4, 0x4, 0x2, 0x8, 0xa, 0x82, 0x7a, 0xb1, 0xc1, 0x0, 0x0, 0x0, 0x0, 0x1,
        0x3, 0x3, 0x7,
    ];
    println!("{:x?}", ones_complement_sum_byte_buffer(&buf));
}
