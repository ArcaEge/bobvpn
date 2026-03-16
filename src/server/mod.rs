use tun_tap::Iface;

pub fn run(iface: &Iface) -> ! {
    // That 1500 is a guess for the IFace's MTU (we probably could configure it explicitly). 4 more
    // for TUN's "header".
    let mut buffer = vec![0; 1504];

    loop {
        // Every read is one packet. If the buffer is too small, bad luck, it gets truncated.
        let size = iface.recv(&mut buffer).unwrap();
        assert!(size >= 4);
        println!("Packet: {:?}", &buffer[4..size]);
    }
}
