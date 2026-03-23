use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::config::WebServerConfig;
use crate::metrics::MetricsCollector;

/// Simple embedded HTTP server for dashboard and admin API
pub struct DashboardServer {
    config: WebServerConfig,
    metrics: Arc<MetricsCollector>,
}

impl DashboardServer {
    pub fn new(config: WebServerConfig, metrics: Arc<MetricsCollector>) -> Self {
        Self { config, metrics }
    }

    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<bool>) {
        let addr = format!("{}:{}", self.config.addr, self.config.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind dashboard server at {}: {}", addr, e);
                return;
            }
        };

        info!("Dashboard server listening at {}", addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((mut stream, peer_addr)) => {
                            let metrics = self.metrics.clone();
                            let user = self.config.user.clone();
                            let password = self.config.password.as_ref().map(|p| p.to_string());
                            let enable_prometheus = true;

                            tokio::spawn(async move {
                                if let Err(e) = handle_request(
                                    &mut stream,
                                    peer_addr,
                                    metrics,
                                    user.as_deref(),
                                    password.as_deref(),
                                    enable_prometheus,
                                ).await {
                                    tracing::debug!("Dashboard request error: {:#}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Dashboard accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Dashboard server shutting down");
                    break;
                }
            }
        }
    }
}

async fn handle_request(
    stream: &mut tokio::net::TcpStream,
    _peer_addr: SocketAddr,
    metrics: Arc<MetricsCollector>,
    auth_user: Option<&str>,
    auth_password: Option<&str>,
    enable_prometheus: bool,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    let (_method, path) = match parts.as_slice() {
        [method, path, ..] => (*method, *path),
        _ => return Ok(()),
    };

    // Basic auth check
    if let (Some(user), Some(pass)) = (auth_user, auth_password) {
        let auth_header = request
            .lines()
            .find(|l| l.to_lowercase().starts_with("authorization:"))
            .map(|l| l.trim());

        let authorized = if let Some(auth_line) = auth_header {
            if let Some(encoded) = auth_line.split_whitespace().last() {
                // Simple base64 check
                let expected = format!("{}:{}", user, pass);
                let expected_b64 = simple_base64_encode(expected.as_bytes());
                encoded == expected_b64
            } else {
                false
            }
        } else {
            false
        };

        if !authorized {
            let response = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"chagle\"\r\nContent-Length: 12\r\n\r\nUnauthorized";
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    }

    match path {
        "/metrics" if enable_prometheus => {
            let body = metrics.prometheus_output().await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/api/status" => {
            let body = metrics.status_json().await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/api/health" => {
            let body = r#"{"status":"ok"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
        "/" => {
            let body = dashboard_html();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
        _ => {
            let body = "Not Found";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

fn simple_base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        output.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < input.len() {
            output.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
        if i + 2 < input.len() {
            output.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
        i += 3;
    }
    output
}

fn dashboard_html() -> String {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Chagle Dashboard</title>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .card { background: white; border-radius: 8px; padding: 20px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
        th { background: #f8f8f8; font-weight: 600; }
        .status-ok { color: #22c55e; }
        .status-err { color: #ef4444; }
        #status { min-height: 100px; }
    </style>
</head>
<body>
    <h1>Chagle Dashboard</h1>
    <div class="card">
        <h2>Proxy Status</h2>
        <div id="status">Loading...</div>
    </div>
    <script>
        async function refresh() {
            try {
                const resp = await fetch('/api/status');
                const data = await resp.json();
                let html = '<table><tr><th>Proxy</th><th>Connections In</th><th>Connections Out</th><th>Bytes In</th><th>Bytes Out</th></tr>';
                for (const [name, stats] of Object.entries(data)) {
                    html += `<tr><td>${name}</td><td>${stats.connections_in}</td><td>${stats.connections_out}</td><td>${formatBytes(stats.bytes_in)}</td><td>${formatBytes(stats.bytes_out)}</td></tr>`;
                }
                html += '</table>';
                document.getElementById('status').innerHTML = html;
            } catch(e) {
                document.getElementById('status').innerHTML = '<p class="status-err">Failed to load status</p>';
            }
        }
        function formatBytes(b) {
            if (b > 1073741824) return (b/1073741824).toFixed(2) + ' GB';
            if (b > 1048576) return (b/1048576).toFixed(2) + ' MB';
            if (b > 1024) return (b/1024).toFixed(2) + ' KB';
            return b + ' B';
        }
        refresh();
        setInterval(refresh, 5000);
    </script>
</body>
</html>"#.to_string()
}
