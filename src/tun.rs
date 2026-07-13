use std::sync::Arc;
use tun_rs::AsyncDevice;

pub struct TunDevice {
    inner: Arc<AsyncDevice>,
}

impl TunDevice {
    pub fn new(inner: AsyncDevice) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    pub async fn send_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }

}

impl Clone for TunDevice {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
