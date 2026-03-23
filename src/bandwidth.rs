#![allow(dead_code)]
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Token bucket rate limiter for bandwidth limiting
pub struct TokenBucket {
    rate: u64,       // bytes per second
    tokens: f64,     // current tokens
    max_tokens: f64, // max burst size
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(bytes_per_sec: u64) -> Self {
        let max_tokens = bytes_per_sec as f64;
        Self {
            rate: bytes_per_sec,
            tokens: max_tokens,
            max_tokens,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.max_tokens);
        self.last_refill = now;
    }

    pub fn consume(&mut self, bytes: usize) -> bool {
        self.refill();
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    pub fn available(&mut self) -> usize {
        self.refill();
        self.tokens as usize
    }
}

/// A wrapper around an AsyncRead + AsyncWrite stream that limits bandwidth
pub struct BandwidthLimitedStream<S> {
    inner: S,
    read_limiter: Option<TokenBucket>,
    write_limiter: Option<TokenBucket>,
}

impl<S> BandwidthLimitedStream<S> {
    pub fn new(inner: S, limit_bytes_per_sec: u64) -> Self {
        let limiter = if limit_bytes_per_sec > 0 {
            Some(TokenBucket::new(limit_bytes_per_sec))
        } else {
            None
        };
        let write_limiter = if limit_bytes_per_sec > 0 {
            Some(TokenBucket::new(limit_bytes_per_sec))
        } else {
            None
        };
        Self {
            inner,
            read_limiter: limiter,
            write_limiter,
        }
    }

    pub fn new_read_only(inner: S, limit_bytes_per_sec: u64) -> Self {
        let limiter = if limit_bytes_per_sec > 0 {
            Some(TokenBucket::new(limit_bytes_per_sec))
        } else {
            None
        };
        Self {
            inner,
            read_limiter: limiter,
            write_limiter: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BandwidthLimitedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if let Some(limiter) = &mut this.read_limiter {
            let available = limiter.available();
            if available == 0 {
                // Schedule a wake-up after a short delay
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    waker.wake();
                });
                return Poll::Pending;
            }

            // Limit the read buffer to available tokens
            let max_read = available.min(buf.remaining());
            let mut limited_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..max_read]);

            match Pin::new(&mut this.inner).poll_read(cx, &mut limited_buf) {
                Poll::Ready(Ok(())) => {
                    let n = limited_buf.filled().len();
                    limiter.consume(n);
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BandwidthLimitedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if let Some(limiter) = &mut this.write_limiter {
            let available = limiter.available();
            if available == 0 {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    waker.wake();
                });
                return Poll::Pending;
            }

            let max_write = available.min(buf.len());
            match Pin::new(&mut this.inner).poll_write(cx, &buf[..max_write]) {
                Poll::Ready(Ok(n)) => {
                    limiter.consume(n);
                    Poll::Ready(Ok(n))
                }
                other => other,
            }
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for BandwidthLimitedStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthLimitedStream")
            .field("inner", &self.inner)
            .finish()
    }
}
