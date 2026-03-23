#![allow(dead_code)]
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::HealthCheckConfig;

/// Health check status for a service
#[derive(Debug)]
pub struct HealthStatus {
    healthy: AtomicBool,
    consecutive_failures: AtomicU32,
    max_failed: u32,
}

impl HealthStatus {
    pub fn new(max_failed: u32) -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_failures: AtomicU32::new(0),
            max_failed,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.max_failed {
            self.healthy.store(false, Ordering::Relaxed);
        }
    }
}

/// Run a health check loop for a service
pub async fn run_health_check(
    config: HealthCheckConfig,
    local_addr: String,
    status: Arc<HealthStatus>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.interval_seconds);
    let timeout = Duration::from_secs(config.timeout_seconds);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                let result = match config.check_type.as_str() {
                    "tcp" => tcp_health_check(&local_addr, timeout).await,
                    "http" => {
                        let path = config.path.as_deref().unwrap_or("/");
                        let headers = config.http_headers.as_deref();
                        http_health_check(&local_addr, path, headers, timeout).await
                    }
                    _ => {
                        warn!("Unknown health check type: {}", config.check_type);
                        continue;
                    }
                };

                match result {
                    Ok(()) => {
                        debug!("Health check passed for {}", local_addr);
                        status.record_success();
                    }
                    Err(e) => {
                        warn!("Health check failed for {}: {:#}", local_addr, e);
                        status.record_failure();
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }
}

/// TCP health check: just try to connect
async fn tcp_health_check(addr: &str, timeout: Duration) -> Result<()> {
    let _conn = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    Ok(())
}

/// HTTP health check: connect and send GET request, check for 2xx response
async fn http_health_check(
    addr: &str,
    path: &str,
    headers: Option<&[crate::config::HttpHeader]>,
    timeout: Duration,
) -> Result<()> {
    let mut conn = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;

    // Build HTTP request
    let mut request = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, addr);

    if let Some(hdrs) = headers {
        for h in hdrs {
            request.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
    }

    request.push_str("Connection: close\r\n\r\n");

    conn.write_all(request.as_bytes()).await?;

    // Read response (just the status line)
    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await?;

    if n == 0 {
        anyhow::bail!("Empty response");
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    let status_line = response.lines().next().unwrap_or("");

    // Check for HTTP/1.x 2xx
    if let Some(status_str) = status_line.split_whitespace().nth(1) {
        let status: u16 = status_str.parse().unwrap_or(0);
        if (200..300).contains(&status) {
            return Ok(());
        }
        anyhow::bail!("HTTP health check returned status {}", status);
    }

    anyhow::bail!("Invalid HTTP response: {}", status_line);
}
