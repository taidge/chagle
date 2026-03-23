use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::path::Path;
use tokio::fs;
use url::Url;

use crate::transport::{DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_KEEPALIVE_SECS, DEFAULT_NODELAY};

/// Application-layer heartbeat interval in secs
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 40;

/// Client
const DEFAULT_CLIENT_RETRY_INTERVAL_SECS: u64 = 1;

/// String with Debug implementation that emits "MASKED"
/// Used to mask sensitive strings when logging
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone)]
pub struct MaskedString(String);

impl Debug for MaskedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str("MASKED")
    }
}

impl Deref for MaskedString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&str> for MaskedString {
    fn from(s: &str) -> MaskedString {
        MaskedString(String::from(s))
    }
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Default)]
pub enum TransportType {
    #[default]
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "noise")]
    Noise,
    #[serde(rename = "websocket")]
    Websocket,
    #[serde(rename = "kcp")]
    Kcp,
    #[serde(rename = "quic")]
    Quic,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceType {
    #[serde(rename = "tcp")]
    #[default]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
    #[serde(rename = "tcpmux")]
    Tcpmux,
    #[serde(rename = "stcp")]
    Stcp,
    #[serde(rename = "sudp")]
    Sudp,
    #[serde(rename = "xtcp")]
    Xtcp,
}

fn default_service_type() -> ServiceType {
    Default::default()
}

// ---------- Port range for allow_ports ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

// ---------- Health check config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(rename = "type", default = "default_health_check_type")]
    pub check_type: String,
    pub path: Option<String>,
    #[serde(default = "default_health_check_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_check_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_health_check_max_failed")]
    pub max_failed: u32,
    pub http_headers: Option<Vec<HttpHeader>>,
}

fn default_health_check_type() -> String {
    "tcp".to_string()
}

fn default_health_check_interval() -> u64 {
    10
}

fn default_health_check_timeout() -> u64 {
    3
}

fn default_health_check_max_failed() -> u32 {
    3
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

// ---------- Load balancer config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancerConfig {
    pub group: String,
    pub group_key: Option<MaskedString>,
}

// ---------- Web server config (dashboard / admin API) ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebServerConfig {
    #[serde(default = "default_web_addr")]
    pub addr: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<MaskedString>,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
}

fn default_web_addr() -> String {
    "127.0.0.1".to_string()
}

// ---------- Log config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    pub to: Option<String>,
    pub level: Option<String>,
    pub max_days: Option<u64>,
    #[serde(default)]
    pub disable_print_color: bool,
}

// ---------- KCP config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KcpConfig {
    #[serde(default = "default_kcp_mode")]
    pub mode: String,
    #[serde(default = "default_kcp_mtu")]
    pub mtu: u32,
    #[serde(default = "default_kcp_sndwnd")]
    pub sndwnd: u32,
    #[serde(default = "default_kcp_rcvwnd")]
    pub rcvwnd: u32,
}

fn default_kcp_mode() -> String {
    "fast".to_string()
}

fn default_kcp_mtu() -> u32 {
    1350
}

fn default_kcp_sndwnd() -> u32 {
    1024
}

fn default_kcp_rcvwnd() -> u32 {
    1024
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mode: default_kcp_mode(),
            mtu: default_kcp_mtu(),
            sndwnd: default_kcp_sndwnd(),
            rcvwnd: default_kcp_rcvwnd(),
        }
    }
}

// ---------- QUIC config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    #[serde(default = "default_quic_keepalive")]
    pub keepalive_period: u64,
    #[serde(default = "default_quic_max_idle_timeout")]
    pub max_idle_timeout: u64,
    #[serde(default = "default_quic_max_streams")]
    pub max_incoming_streams: u32,
}

fn default_quic_keepalive() -> u64 {
    10
}

fn default_quic_max_idle_timeout() -> u64 {
    30
}

fn default_quic_max_streams() -> u32 {
    100
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keepalive_period: default_quic_keepalive(),
            max_idle_timeout: default_quic_max_idle_timeout(),
            max_incoming_streams: default_quic_max_streams(),
        }
    }
}

// ---------- Client plugin config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientPluginConfig {
    #[serde(rename = "type")]
    pub plugin_type: String,
    pub local_addr: Option<String>,
    pub host_header_rewrite: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<MaskedString>,
    pub local_path: Option<String>,
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub enable_http2: bool,
    pub unix_path: Option<String>,
    pub crt_path: Option<String>,
    pub key_path: Option<String>,
}

// ---------- OIDC config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcClientConfig {
    pub client_id: String,
    pub client_secret: MaskedString,
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub token_endpoint_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcServerConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub skip_expiry_check: bool,
    #[serde(default)]
    pub skip_issuer_check: bool,
}

// ---------- Auth config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default = "default_auth_method")]
    pub method: String,
    pub token: Option<MaskedString>,
    pub token_file: Option<String>,
    pub oidc: Option<OidcClientConfig>,
    pub oidc_server: Option<OidcServerConfig>,
}

fn default_auth_method() -> String {
    "token".to_string()
}

// ---------- SSH tunnel gateway config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshTunnelGatewayConfig {
    pub bind_port: u16,
    pub private_key_file: Option<String>,
    pub auto_gen_private_key_path: Option<String>,
    pub authorized_keys_file: Option<String>,
}

// ---------- Server plugin config ----------

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerPluginConfig {
    pub name: String,
    pub addr: String,
    pub path: String,
    pub ops: Vec<String>,
    #[serde(default)]
    pub tls_verify: bool,
}

// ---------- Client service config ----------

/// Per service config
/// All Option are optional in configuration but must be Some value in runtime
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientServiceConfig {
    #[serde(rename = "type", default = "default_service_type")]
    pub service_type: ServiceType,
    #[serde(skip)]
    pub name: String,
    #[serde(default)]
    pub local_addr: String,
    #[serde(default)] // Default to false
    pub prefer_ipv6: bool,
    pub token: Option<MaskedString>,
    pub nodelay: Option<bool>,
    pub retry_interval: Option<u64>,

    // --- Phase 1: Infrastructure ---
    pub enabled: Option<bool>,
    pub pool_count: Option<usize>,
    pub bandwidth_limit: Option<String>,
    pub proxy_protocol_version: Option<String>,
    #[serde(default)]
    pub use_encryption: bool,
    #[serde(default)]
    pub use_compression: bool,
    pub metadatas: Option<HashMap<String, String>>,

    // --- Phase 2: HTTP/HTTPS ---
    pub custom_domains: Option<Vec<String>>,
    pub subdomain: Option<String>,
    pub locations: Option<Vec<String>>,
    pub host_header_rewrite: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<MaskedString>,
    pub request_headers: Option<HashMap<String, String>>,
    pub response_headers: Option<HashMap<String, String>>,
    pub route_by_http_user: Option<String>,

    // --- Phase 3: Secret / P2P ---
    pub secret_key: Option<MaskedString>,
    pub server_user: Option<String>,
    pub server_name: Option<String>,
    pub bind_addr: Option<String>,
    pub bind_port: Option<i32>,
    pub allow_users: Option<Vec<String>>,
    #[serde(default)]
    pub keep_tunnel_open: bool,
    pub max_retries_an_hour: Option<u32>,
    pub min_retry_interval: Option<u64>,
    pub fallback_to: Option<String>,
    pub fallback_timeout_ms: Option<u64>,

    // --- Phase 5: Health check & Load balancing ---
    pub health_check: Option<HealthCheckConfig>,
    pub load_balancer: Option<LoadBalancerConfig>,

    // --- Phase 7: Plugin ---
    pub plugin: Option<ClientPluginConfig>,
}

impl ClientServiceConfig {
    pub fn with_name(name: &str) -> ClientServiceConfig {
        ClientServiceConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn is_visitor(&self) -> bool {
        matches!(
            self.service_type,
            ServiceType::Stcp | ServiceType::Sudp | ServiceType::Xtcp
        ) && self.server_name.is_some()
    }
}

// ---------- Server service config ----------

/// Per service config
/// All Option are optional in configuration but must be Some value in runtime
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerServiceConfig {
    #[serde(rename = "type", default = "default_service_type")]
    pub service_type: ServiceType,
    #[serde(skip)]
    pub name: String,
    #[serde(default)]
    pub bind_addr: String,
    pub token: Option<MaskedString>,
    pub nodelay: Option<bool>,

    // --- Phase 1: Infrastructure ---
    pub enabled: Option<bool>,
    pub pool_count: Option<usize>,
    pub bandwidth_limit: Option<String>,
    pub proxy_protocol_version: Option<String>,
    pub metadatas: Option<HashMap<String, String>>,

    // --- Phase 2: HTTP/HTTPS ---
    pub custom_domains: Option<Vec<String>>,
    pub subdomain: Option<String>,
    pub locations: Option<Vec<String>>,
    pub host_header_rewrite: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<MaskedString>,
    pub request_headers: Option<HashMap<String, String>>,
    pub response_headers: Option<HashMap<String, String>>,
    pub route_by_http_user: Option<String>,

    // --- Phase 3: Secret / P2P ---
    pub secret_key: Option<MaskedString>,
    pub allow_users: Option<Vec<String>>,

    // --- Phase 5: Health check & Load balancing ---
    pub health_check: Option<HealthCheckConfig>,
    pub load_balancer: Option<LoadBalancerConfig>,
}

impl ServerServiceConfig {
    pub fn with_name(name: &str) -> ServerServiceConfig {
        ServerServiceConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn pool_size(&self) -> usize {
        if let Some(count) = self.pool_count {
            return count;
        }
        match self.service_type {
            ServiceType::Tcp
            | ServiceType::Http
            | ServiceType::Https
            | ServiceType::Tcpmux
            | ServiceType::Stcp => 8,
            ServiceType::Udp | ServiceType::Sudp => 2,
            ServiceType::Xtcp => 1,
        }
    }

    pub fn needs_bind_addr(&self) -> bool {
        matches!(self.service_type, ServiceType::Tcp | ServiceType::Udp)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub hostname: Option<String>,
    pub trusted_root: Option<String>,
    pub pkcs12: Option<String>,
    pub pkcs12_password: Option<MaskedString>,
    // Mutual TLS (Phase 4)
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    #[serde(default)]
    pub force: bool,
}

fn default_noise_pattern() -> String {
    String::from("Noise_NK_25519_ChaChaPoly_BLAKE2s")
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NoiseConfig {
    #[serde(default = "default_noise_pattern")]
    pub pattern: String,
    pub local_private_key: Option<MaskedString>,
    pub remote_public_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebsocketConfig {
    pub tls: bool,
}

fn default_nodelay() -> bool {
    DEFAULT_NODELAY
}

fn default_keepalive_secs() -> u64 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_keepalive_interval() -> u64 {
    DEFAULT_KEEPALIVE_INTERVAL
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
    pub proxy: Option<Url>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            nodelay: default_nodelay(),
            keepalive_secs: default_keepalive_secs(),
            keepalive_interval: default_keepalive_interval(),
            proxy: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub transport_type: TransportType,
    #[serde(default)]
    pub tcp: TcpConfig,
    pub tls: Option<TlsConfig>,
    pub noise: Option<NoiseConfig>,
    pub websocket: Option<WebsocketConfig>,
    pub kcp: Option<KcpConfig>,
    pub quic: Option<QuicConfig>,
    // TCP stream multiplexing (Phase 4)
    #[serde(default = "default_tcp_mux")]
    pub tcp_mux: bool,
    #[serde(default = "default_tcp_mux_keepalive")]
    pub tcp_mux_keepalive_interval: u64,
    // Connection pooling
    pub pool_count: Option<usize>,
    // Heartbeat
    pub heartbeat_interval: Option<i64>,
    pub heartbeat_timeout: Option<i64>,
}

fn default_tcp_mux() -> bool {
    true
}

fn default_tcp_mux_keepalive() -> u64 {
    30
}

fn default_heartbeat_timeout() -> u64 {
    DEFAULT_HEARTBEAT_TIMEOUT_SECS
}

fn default_client_retry_interval() -> u64 {
    DEFAULT_CLIENT_RETRY_INTERVAL_SECS
}

fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL_SECS
}

// ---------- Client config ----------

#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub remote_addr: String,
    pub default_token: Option<MaskedString>,
    pub prefer_ipv6: Option<bool>,
    pub services: HashMap<String, ClientServiceConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,
    #[serde(default = "default_client_retry_interval")]
    pub retry_interval: u64,

    // --- Phase 1 ---
    pub user: Option<String>,
    pub dns_server: Option<String>,
    pub log: Option<LogConfig>,

    // --- Phase 6: Admin API ---
    pub web_server: Option<WebServerConfig>,

    // --- Phase 8: Config ---
    pub start: Option<Vec<String>>,
    pub includes: Option<Vec<String>>,

    // --- Phase 9: Auth ---
    pub auth: Option<AuthConfig>,
}

// ---------- Server config ----------

#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub default_token: Option<MaskedString>,
    pub services: HashMap<String, ServerServiceConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    // --- Phase 1: Infrastructure ---
    pub allow_ports: Option<Vec<PortRange>>,
    pub max_ports_per_client: Option<u32>,
    #[serde(default = "default_detailed_errors")]
    pub detailed_errors_to_client: bool,
    pub dns_server: Option<String>,
    pub log: Option<LogConfig>,

    // --- Phase 2: HTTP/HTTPS ---
    pub vhost_http_port: Option<u16>,
    pub vhost_https_port: Option<u16>,
    pub subdomain_host: Option<String>,
    pub custom_404_page: Option<String>,

    // --- Phase 2: TCPMUX ---
    pub tcpmux_http_connect_port: Option<u16>,

    // --- Phase 3: P2P ---
    pub nat_hole_stun_server: Option<String>,

    // --- Phase 6: Dashboard ---
    pub web_server: Option<WebServerConfig>,
    #[serde(default)]
    pub enable_prometheus: bool,

    // --- Phase 7: Server plugins ---
    pub http_plugins: Option<Vec<ServerPluginConfig>>,

    // --- Phase 9: Auth ---
    pub auth: Option<AuthConfig>,

    // --- Phase 10: SSH Gateway ---
    pub ssh_tunnel_gateway: Option<SshTunnelGatewayConfig>,
}

fn default_detailed_errors() -> bool {
    true
}

// ---------- Top-level config ----------

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

impl Config {
    fn from_str(s: &str) -> Result<Config> {
        let mut config: Config = toml::from_str(s).with_context(|| "Failed to parse the config")?;

        if let Some(server) = config.server.as_mut() {
            Config::validate_server_config(server)?;
        }

        if let Some(client) = config.client.as_mut() {
            Config::validate_client_config(client)?;
        }

        if config.server.is_none() && config.client.is_none() {
            Err(anyhow!("Neither of `[server]` or `[client]` is defined"))
        } else {
            Ok(config)
        }
    }

    fn validate_server_config(server: &mut ServerConfig) -> Result<()> {
        // Validate services
        for (name, s) in &mut server.services {
            s.name = name.clone();

            // Skip disabled services
            if !s.is_enabled() {
                continue;
            }

            // Token handling: use auth config, default_token, or service token
            if s.token.is_none() {
                if let Some(auth) = &server.auth {
                    s.token = auth.token.clone();
                }
                if s.token.is_none() {
                    s.token = server.default_token.clone();
                }
                if s.token.is_none() {
                    bail!("The token of service {} is not set", name);
                }
            }

            // Validate bind_addr is set for TCP/UDP services
            if s.needs_bind_addr() && s.bind_addr.is_empty() {
                bail!("Service {} requires `bind_addr`", name);
            }

            // Validate HTTP/HTTPS services
            if matches!(s.service_type, ServiceType::Http | ServiceType::Https) {
                if s.custom_domains.is_none() && s.subdomain.is_none() {
                    bail!(
                        "Service {} of type {:?} requires `custom_domains` or `subdomain`",
                        name,
                        s.service_type
                    );
                }
            }

            // Validate STCP/SUDP/XTCP services
            if matches!(
                s.service_type,
                ServiceType::Stcp | ServiceType::Sudp | ServiceType::Xtcp
            ) && s.secret_key.is_none()
            {
                bail!(
                    "Service {} of type {:?} requires `secret_key`",
                    name,
                    s.service_type
                );
            }

            // Validate port restrictions
            if let Some(allow_ports) = &server.allow_ports {
                if s.needs_bind_addr() && !s.bind_addr.is_empty() {
                    if let Ok(port) = s.bind_addr.rsplit(':').next().unwrap_or("0").parse::<u16>() {
                        if port > 0 && !allow_ports.iter().any(|r| r.contains(port)) {
                            bail!(
                                "Service {} uses port {} which is not in allow_ports",
                                name,
                                port
                            );
                        }
                    }
                }
            }

            // Validate health check
            if let Some(hc) = &s.health_check {
                if hc.check_type != "tcp" && hc.check_type != "http" {
                    bail!(
                        "Service {} health_check.type must be 'tcp' or 'http', got '{}'",
                        name,
                        hc.check_type
                    );
                }
                if hc.check_type == "http" && hc.path.is_none() {
                    bail!("Service {} HTTP health_check requires `path`", name);
                }
            }

            // Validate bandwidth_limit format
            if let Some(bw) = &s.bandwidth_limit {
                parse_bandwidth_limit(bw).with_context(|| {
                    format!("Service {} has invalid bandwidth_limit '{}'", name, bw)
                })?;
            }

            // Validate proxy_protocol_version
            if let Some(ppv) = &s.proxy_protocol_version {
                if ppv != "v1" && ppv != "v2" {
                    bail!(
                        "Service {} proxy_protocol_version must be 'v1' or 'v2', got '{}'",
                        name,
                        ppv
                    );
                }
            }
        }

        Config::validate_transport_config(&server.transport, true)?;

        // Validate HTTP vhost port
        if server.vhost_http_port.is_some() || server.vhost_https_port.is_some() {
            let has_http_service = server.services.values().any(|s| {
                s.is_enabled() && matches!(s.service_type, ServiceType::Http | ServiceType::Https)
            });
            if !has_http_service {
                // Just a warning case, not an error - port can be configured in advance
            }
        }

        Ok(())
    }

    fn validate_client_config(client: &mut ClientConfig) -> Result<()> {
        let start_filter = client.start.as_ref();

        // Validate services
        for (name, s) in &mut client.services {
            s.name = name.clone();

            // Apply user prefix
            if let Some(user) = &client.user {
                s.name = format!("{}.{}", user, name);
            }

            // Skip disabled services
            if !s.is_enabled() {
                continue;
            }

            // Apply start filter
            if let Some(start) = start_filter {
                if !start.contains(name) {
                    continue;
                }
            }

            // Token handling
            if s.token.is_none() {
                if let Some(auth) = &client.auth {
                    s.token = auth.token.clone();
                }
                if s.token.is_none() {
                    s.token = client.default_token.clone();
                }
                if s.token.is_none() {
                    bail!("The token of service {} is not set", name);
                }
            }

            if s.retry_interval.is_none() {
                s.retry_interval = Some(client.retry_interval);
            }

            // Apply global prefer_ipv6
            if let Some(prefer_ipv6) = client.prefer_ipv6 {
                if !s.prefer_ipv6 {
                    s.prefer_ipv6 = prefer_ipv6;
                }
            }

            // Validate visitor services
            if s.is_visitor() {
                if s.bind_port.is_none() && s.plugin.is_none() {
                    // Visitors need either a bind_port or a plugin
                }
            } else if !matches!(s.service_type, ServiceType::Http | ServiceType::Https)
                && s.local_addr.is_empty()
                && s.plugin.is_none()
            {
                bail!("Service {} requires `local_addr` or `plugin`", name);
            }

            // Validate bandwidth_limit format
            if let Some(bw) = &s.bandwidth_limit {
                parse_bandwidth_limit(bw).with_context(|| {
                    format!("Service {} has invalid bandwidth_limit '{}'", name, bw)
                })?;
            }
        }

        Config::validate_transport_config(&client.transport, false)?;

        Ok(())
    }

    fn validate_transport_config(config: &TransportConfig, is_server: bool) -> Result<()> {
        config
            .tcp
            .proxy
            .as_ref()
            .map_or(Ok(()), |u| match u.scheme() {
                "socks5" => Ok(()),
                "http" => Ok(()),
                _ => Err(anyhow!(format!("Unknown proxy scheme: {}", u.scheme()))),
            })?;
        match config.transport_type {
            TransportType::Tcp => Ok(()),
            TransportType::Tls => {
                let tls_config = config
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing TLS configuration"))?;
                if is_server {
                    tls_config
                        .pkcs12
                        .as_ref()
                        .and(tls_config.pkcs12_password.as_ref())
                        .ok_or_else(|| anyhow!("Missing `pkcs12` or `pkcs12_password`"))?;
                }
                Ok(())
            }
            TransportType::Noise => {
                // The check is done in transport
                Ok(())
            }
            TransportType::Websocket => Ok(()),
            TransportType::Kcp => {
                // KCP uses UDP, config is optional with defaults
                Ok(())
            }
            TransportType::Quic => {
                // QUIC config is optional with defaults
                // Server needs TLS config for QUIC
                if is_server {
                    let tls = config
                        .tls
                        .as_ref()
                        .ok_or_else(|| anyhow!("QUIC transport requires TLS configuration"))?;
                    tls.pkcs12
                        .as_ref()
                        .and(tls.pkcs12_password.as_ref())
                        .ok_or_else(|| {
                            anyhow!("QUIC transport requires `pkcs12` and `pkcs12_password`")
                        })?;
                }
                Ok(())
            }
        }
    }

    pub async fn from_file(path: &Path) -> Result<Config> {
        let s: String = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read the config {:?}", path))?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("toml");

        match ext {
            "yaml" | "yml" => Config::from_yaml(&s),
            "json" => Config::from_json(&s),
            _ => Config::from_str(&s),
        }
        .with_context(
            || "Configuration is invalid. Please refer to the configuration specification.",
        )
    }

    fn from_yaml(s: &str) -> Result<Config> {
        let mut config: Config =
            serde_yaml::from_str(s).with_context(|| "Failed to parse YAML config")?;
        if let Some(server) = config.server.as_mut() {
            Config::validate_server_config(server)?;
        }
        if let Some(client) = config.client.as_mut() {
            Config::validate_client_config(client)?;
        }
        if config.server.is_none() && config.client.is_none() {
            Err(anyhow!("Neither of `[server]` or `[client]` is defined"))
        } else {
            Ok(config)
        }
    }

    fn from_json(s: &str) -> Result<Config> {
        let mut config: Config =
            serde_json::from_str(s).with_context(|| "Failed to parse JSON config")?;
        if let Some(server) = config.server.as_mut() {
            Config::validate_server_config(server)?;
        }
        if let Some(client) = config.client.as_mut() {
            Config::validate_client_config(client)?;
        }
        if config.server.is_none() && config.client.is_none() {
            Err(anyhow!("Neither of `[server]` or `[client]` is defined"))
        } else {
            Ok(config)
        }
    }
}

/// Parse bandwidth limit string like "1MB", "500KB" into bytes per second
pub fn parse_bandwidth_limit(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let (num_str, unit) = if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024u64 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024u64)
    } else if s.ends_with("B") {
        (&s[..s.len() - 1], 1u64)
    } else {
        bail!("Invalid bandwidth unit. Use MB, KB, or B");
    };
    let num: f64 = num_str
        .trim()
        .parse()
        .with_context(|| format!("Invalid bandwidth number: {}", num_str))?;
    Ok((num * unit as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use anyhow::Result;

    fn list_config_files<T: AsRef<Path>>(root: T) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                files.append(&mut list_config_files(path)?);
            }
        }
        Ok(files)
    }

    fn get_all_example_config() -> Result<Vec<PathBuf>> {
        Ok(list_config_files("./examples")?
            .into_iter()
            .filter(|x| x.ends_with(".toml"))
            .collect())
    }

    #[test]
    fn test_example_config() -> Result<()> {
        let paths = get_all_example_config()?;
        for p in paths {
            let s = fs::read_to_string(p)?;
            Config::from_str(&s)?;
        }
        Ok(())
    }

    #[test]
    fn test_valid_config() -> Result<()> {
        let paths = list_config_files("tests/config_test/valid_config")?;
        for p in paths {
            let s = fs::read_to_string(p)?;
            Config::from_str(&s)?;
        }
        Ok(())
    }

    #[test]
    fn test_invalid_config() -> Result<()> {
        let paths = list_config_files("tests/config_test/invalid_config")?;
        for p in paths {
            let s = fs::read_to_string(p)?;
            assert!(Config::from_str(&s).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_validate_server_config() -> Result<()> {
        let mut cfg = ServerConfig::default();

        cfg.services.insert(
            "foo1".into(),
            ServerServiceConfig {
                service_type: ServiceType::Tcp,
                name: "foo1".into(),
                bind_addr: "127.0.0.1:80".into(),
                token: None,
                ..Default::default()
            },
        );

        // Missing the token
        assert!(Config::validate_server_config(&mut cfg).is_err());

        // Use the default token
        cfg.default_token = Some("123".into());
        assert!(Config::validate_server_config(&mut cfg).is_ok());
        assert_eq!(
            cfg.services
                .get("foo1")
                .as_ref()
                .unwrap()
                .token
                .as_ref()
                .unwrap()
                .0,
            "123"
        );

        // The default token won't override the service token
        cfg.services.get_mut("foo1").unwrap().token = Some("4".into());
        assert!(Config::validate_server_config(&mut cfg).is_ok());
        assert_eq!(
            cfg.services
                .get("foo1")
                .as_ref()
                .unwrap()
                .token
                .as_ref()
                .unwrap()
                .0,
            "4"
        );
        Ok(())
    }

    #[test]
    fn test_validate_client_config() -> Result<()> {
        let mut cfg = ClientConfig::default();

        cfg.services.insert(
            "foo1".into(),
            ClientServiceConfig {
                service_type: ServiceType::Tcp,
                name: "foo1".into(),
                local_addr: "127.0.0.1:80".into(),
                token: None,
                ..Default::default()
            },
        );

        // Missing the token
        assert!(Config::validate_client_config(&mut cfg).is_err());

        // Use the default token
        cfg.default_token = Some("123".into());
        assert!(Config::validate_client_config(&mut cfg).is_ok());
        assert_eq!(
            cfg.services
                .get("foo1")
                .as_ref()
                .unwrap()
                .token
                .as_ref()
                .unwrap()
                .0,
            "123"
        );

        // The default token won't override the service token
        cfg.services.get_mut("foo1").unwrap().token = Some("4".into());
        assert!(Config::validate_client_config(&mut cfg).is_ok());
        assert_eq!(
            cfg.services
                .get("foo1")
                .as_ref()
                .unwrap()
                .token
                .as_ref()
                .unwrap()
                .0,
            "4"
        );
        Ok(())
    }

    #[test]
    fn test_parse_bandwidth_limit() -> Result<()> {
        assert_eq!(parse_bandwidth_limit("1MB")?, 1024 * 1024);
        assert_eq!(parse_bandwidth_limit("500KB")?, 500 * 1024);
        assert_eq!(parse_bandwidth_limit("100B")?, 100);
        assert_eq!(parse_bandwidth_limit("")?, 0);
        assert!(parse_bandwidth_limit("abc").is_err());
        assert!(parse_bandwidth_limit("1GB").is_err());
        Ok(())
    }

    #[test]
    fn test_port_range() {
        let r = PortRange {
            start: 8000,
            end: 9000,
        };
        assert!(r.contains(8000));
        assert!(r.contains(8500));
        assert!(r.contains(9000));
        assert!(!r.contains(7999));
        assert!(!r.contains(9001));
    }
}
