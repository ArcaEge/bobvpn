use parking_lot::Mutex;
use std::net::{SocketAddrV4, TcpStream};
use tun_tap::Iface;

pub struct Peer {
    endpoint: Mutex<Option<SocketAddrV4>>,
}

pub struct Device {
    tcp: TcpStream,
    iface: Iface,
    peer: Peer,
}
