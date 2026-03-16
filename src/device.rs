use std::{io::Result, net::TcpStream};
use tun_tap::Iface;

use crate::peer::Peer;

pub struct Device {
    tcp: TcpStream,
    iface: Iface,
    peer: Peer,
}

impl Device {
    fn loop_listen_iface(&self) -> Result<()> {
        let mut buf = [0u8; 1504];

        loop {
            
        }
    }
}