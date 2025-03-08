use std::io;

use tun_tap::{ Iface, Mode };

fn main() -> io::Result<()>  {
    let iface = Iface::new("tun0", Mode::Tun)?;
    // Configure the device ‒ set IP address on it, bring it up.
    let mut buf = vec![0; 1504]; // MTU + 4 for the header
    loop{
        iface.recv(&mut buf)?; // Wait until a packet arrives
        println!("{:?}", buf);
    }
}
