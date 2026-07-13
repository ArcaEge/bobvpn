pub mod client;
pub mod http_fallback;
pub mod http_server;
pub mod server;

use anyhow::{ensure, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const FRAME_DATA: u8 = 0x01;
pub const FRAME_KEEPALIVE: u8 = 0x02;
pub const FRAME_AUTH: u8 = 0x03;
pub const FRAME_KEY_EXCHANGE: u8 = 0x04;

pub fn encode(frame_type: u8, payload: &[u8]) -> Result<Bytes> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "payload too large for frame"
    );
    let mut buf = BytesMut::with_capacity(3 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_u8(frame_type);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

pub fn decode(buf: &mut BytesMut) -> Result<Option<(u8, Bytes)>> {
    if buf.len() < 3 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    ensure!(buf.len() >= 3 + len, "incomplete frame");
    let frame_type = buf[2];
    buf.advance(3);
    let payload = buf.split_to(len).freeze();
    Ok(Some((frame_type, payload)))
}
