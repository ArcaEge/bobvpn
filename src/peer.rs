use parking_lot::Mutex;
use std::{net::SocketAddrV4};

pub struct Peer {
    endpoint: Mutex<Option<SocketAddrV4>>,
}

impl Peer {
}