#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Per-proxy metrics
#[derive(Debug, Default)]
pub struct ProxyMetrics {
    pub connections_in: AtomicU64,
    pub connections_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl ProxyMetrics {
    pub fn record_connection_in(&self) {
        self.connections_in.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_out(&self) {
        self.connections_out.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_in: self.connections_in.load(Ordering::Relaxed),
            connections_out: self.connections_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub connections_in: u64,
    pub connections_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Global metrics collector
#[derive(Debug)]
pub struct MetricsCollector {
    proxies: RwLock<HashMap<String, Arc<ProxyMetrics>>>,
    server_metrics: ServerMetrics,
}

#[derive(Debug, Default)]
pub struct ServerMetrics {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_proxies: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(HashMap::new()),
            server_metrics: ServerMetrics::default(),
        }
    }

    pub async fn get_or_create_proxy(&self, name: &str) -> Arc<ProxyMetrics> {
        {
            let proxies = self.proxies.read().await;
            if let Some(m) = proxies.get(name) {
                return m.clone();
            }
        }

        let mut proxies = self.proxies.write().await;
        proxies
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(ProxyMetrics::default()))
            .clone()
    }

    pub async fn remove_proxy(&self, name: &str) {
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
    }

    pub fn record_connection(&self) {
        self.server_metrics
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
        self.server_metrics
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_disconnection(&self) {
        self.server_metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Generate Prometheus-format metrics output
    pub async fn prometheus_output(&self) -> String {
        let mut output = String::new();

        // Server-level metrics
        output.push_str("# HELP chagle_server_connections_total Total connections received\n");
        output.push_str("# TYPE chagle_server_connections_total counter\n");
        output.push_str(&format!(
            "chagle_server_connections_total {}\n",
            self.server_metrics
                .total_connections
                .load(Ordering::Relaxed)
        ));

        output.push_str("# HELP chagle_server_connections_active Active connections\n");
        output.push_str("# TYPE chagle_server_connections_active gauge\n");
        output.push_str(&format!(
            "chagle_server_connections_active {}\n",
            self.server_metrics
                .active_connections
                .load(Ordering::Relaxed)
        ));

        // Per-proxy metrics
        let proxies = self.proxies.read().await;

        output.push_str("\n# HELP chagle_proxy_connections_in Inbound connections per proxy\n");
        output.push_str("# TYPE chagle_proxy_connections_in counter\n");
        for (name, m) in proxies.iter() {
            output.push_str(&format!(
                "chagle_proxy_connections_in{{proxy=\"{}\"}} {}\n",
                name,
                m.connections_in.load(Ordering::Relaxed)
            ));
        }

        output.push_str("\n# HELP chagle_proxy_connections_out Outbound connections per proxy\n");
        output.push_str("# TYPE chagle_proxy_connections_out counter\n");
        for (name, m) in proxies.iter() {
            output.push_str(&format!(
                "chagle_proxy_connections_out{{proxy=\"{}\"}} {}\n",
                name,
                m.connections_out.load(Ordering::Relaxed)
            ));
        }

        output.push_str("\n# HELP chagle_proxy_bytes_in Bytes received per proxy\n");
        output.push_str("# TYPE chagle_proxy_bytes_in counter\n");
        for (name, m) in proxies.iter() {
            output.push_str(&format!(
                "chagle_proxy_bytes_in{{proxy=\"{}\"}} {}\n",
                name,
                m.bytes_in.load(Ordering::Relaxed)
            ));
        }

        output.push_str("\n# HELP chagle_proxy_bytes_out Bytes sent per proxy\n");
        output.push_str("# TYPE chagle_proxy_bytes_out counter\n");
        for (name, m) in proxies.iter() {
            output.push_str(&format!(
                "chagle_proxy_bytes_out{{proxy=\"{}\"}} {}\n",
                name,
                m.bytes_out.load(Ordering::Relaxed)
            ));
        }

        output
    }

    /// Generate JSON status output for admin API
    pub async fn status_json(&self) -> String {
        let proxies = self.proxies.read().await;
        let mut proxy_stats: HashMap<String, MetricsSnapshot> = HashMap::new();
        for (name, m) in proxies.iter() {
            proxy_stats.insert(name.clone(), m.snapshot());
        }
        serde_json::to_string_pretty(&proxy_stats).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
