use super::SqlCrypt;
use futures_lite::io::AsyncWrite;
use pin_project_lite::pin_project;
use std::io::Result;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

impl super::SqlCrypt {
    pub fn new_decoder<W>(&mut self, inner: W) -> Decoder<W>
    where
        W: AsyncWrite + Unpin,
    {
        let state = Arc::new(Mutex::new(self));
        Decoder { inner, state }
    }
}

pin_project! {
    pub struct Decoder<'a, W> {
        #[pin]
        inner: W,
        state: Arc<Mutex<&'a mut SqlCrypt>>,
    }
}

impl<W> Decoder<'_, W> {
    fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut W> {
        self.project().inner
    }

    fn decode_bytes(&self, buf: &[u8]) -> Vec<u8> {
        let mut decoded = vec![0u8; buf.len()];
        let mut state = self.state.lock().unwrap();
        for (i, &x) in buf.iter().enumerate() {
            decoded[i] = state.decode_byte(x);
        }
        decoded
    }
}

impl<W: AsyncWrite> AsyncWrite for Decoder<'_, W> {
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.as_mut().get_pin_mut().poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.as_mut().get_pin_mut().poll_flush(cx)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let decoded = self.as_mut().decode_bytes(buf);
        self.as_mut().get_pin_mut().poll_write(cx, &decoded)
    }
}
