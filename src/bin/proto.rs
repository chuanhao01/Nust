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
}
