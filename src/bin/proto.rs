fn main() {
    let a = 0b01100010;
    // let a = 0x45;
    let b = a >> 5;
    println!("a: {:#010b}", a);
    println!("a: {}", a);
    println!("b: {:#010b}", b);
    println!("b: {}", b);
}
