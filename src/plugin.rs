#![allow(dead_code)]
use anyhow::Result;
use tokio::net::TcpStream;

use crate::config::ClientPluginConfig;

/// Plugin trait for client-side plugins
/// Plugins intercept local connections and transform them
pub trait ClientPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn plugin_type(&self) -> &str;
}

/// Create a plugin from configuration
pub fn create_plugin(config: &ClientPluginConfig) -> Result<Box<dyn ClientPlugin>> {
    match config.plugin_type.as_str() {
        "http_proxy" => Ok(Box::new(HttpProxyPlugin::new(config)?)),
        "socks5" => Ok(Box::new(Socks5Plugin::new(config)?)),
        "static_file" => Ok(Box::new(StaticFilePlugin::new(config)?)),
        "http2https" => Ok(Box::new(Http2HttpsPlugin::new(config)?)),
        "https2http" => Ok(Box::new(Https2HttpPlugin::new(config)?)),
        "http2http" => Ok(Box::new(Http2HttpPlugin::new(config)?)),
        "https2https" => Ok(Box::new(Https2HttpsPlugin::new(config)?)),
        "tls2raw" => Ok(Box::new(Tls2RawPlugin::new(config)?)),
        "unix_domain_socket" => Ok(Box::new(UnixDomainSocketPlugin::new(config)?)),
        _ => anyhow::bail!("Unknown plugin type: {}", config.plugin_type),
    }
}

// ---------- HTTP Proxy Plugin ----------

pub struct HttpProxyPlugin {
    http_user: Option<String>,
    http_password: Option<String>,
}

impl HttpProxyPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            http_user: config.http_user.clone(),
            http_password: config.http_password.as_ref().map(|p| p.to_string()),
        })
    }
}

impl ClientPlugin for HttpProxyPlugin {
    fn name(&self) -> &str {
        "http_proxy"
    }
    fn plugin_type(&self) -> &str {
        "http_proxy"
    }
}

// ---------- SOCKS5 Plugin ----------

pub struct Socks5Plugin {
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Plugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            username: config.http_user.clone(),
            password: config.http_password.as_ref().map(|p| p.to_string()),
        })
    }
}

impl ClientPlugin for Socks5Plugin {
    fn name(&self) -> &str {
        "socks5"
    }
    fn plugin_type(&self) -> &str {
        "socks5"
    }
}

// ---------- Static File Plugin ----------

pub struct StaticFilePlugin {
    local_path: String,
    strip_prefix: Option<String>,
    http_user: Option<String>,
    http_password: Option<String>,
}

impl StaticFilePlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_path: config.local_path.clone().unwrap_or_else(|| ".".to_string()),
            strip_prefix: config.strip_prefix.clone(),
            http_user: config.http_user.clone(),
            http_password: config.http_password.as_ref().map(|p| p.to_string()),
        })
    }
}

impl ClientPlugin for StaticFilePlugin {
    fn name(&self) -> &str {
        "static_file"
    }
    fn plugin_type(&self) -> &str {
        "static_file"
    }
}

// ---------- Protocol Bridge Plugins ----------

pub struct Http2HttpsPlugin {
    local_addr: String,
    host_header_rewrite: Option<String>,
}

impl Http2HttpsPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_addr: config
                .local_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:443".to_string()),
            host_header_rewrite: config.host_header_rewrite.clone(),
        })
    }
}

impl ClientPlugin for Http2HttpsPlugin {
    fn name(&self) -> &str {
        "http2https"
    }
    fn plugin_type(&self) -> &str {
        "http2https"
    }
}

pub struct Https2HttpPlugin {
    local_addr: String,
    host_header_rewrite: Option<String>,
    crt_path: Option<String>,
    key_path: Option<String>,
}

impl Https2HttpPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_addr: config
                .local_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:80".to_string()),
            host_header_rewrite: config.host_header_rewrite.clone(),
            crt_path: config.crt_path.clone(),
            key_path: config.key_path.clone(),
        })
    }
}

impl ClientPlugin for Https2HttpPlugin {
    fn name(&self) -> &str {
        "https2http"
    }
    fn plugin_type(&self) -> &str {
        "https2http"
    }
}

pub struct Http2HttpPlugin {
    local_addr: String,
    host_header_rewrite: Option<String>,
}

impl Http2HttpPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_addr: config
                .local_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:80".to_string()),
            host_header_rewrite: config.host_header_rewrite.clone(),
        })
    }
}

impl ClientPlugin for Http2HttpPlugin {
    fn name(&self) -> &str {
        "http2http"
    }
    fn plugin_type(&self) -> &str {
        "http2http"
    }
}

pub struct Https2HttpsPlugin {
    local_addr: String,
    host_header_rewrite: Option<String>,
}

impl Https2HttpsPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_addr: config
                .local_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:443".to_string()),
            host_header_rewrite: config.host_header_rewrite.clone(),
        })
    }
}

impl ClientPlugin for Https2HttpsPlugin {
    fn name(&self) -> &str {
        "https2https"
    }
    fn plugin_type(&self) -> &str {
        "https2https"
    }
}

pub struct Tls2RawPlugin {
    local_addr: String,
}

impl Tls2RawPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            local_addr: config
                .local_addr
                .clone()
                .unwrap_or_else(|| "127.0.0.1:0".to_string()),
        })
    }
}

impl ClientPlugin for Tls2RawPlugin {
    fn name(&self) -> &str {
        "tls2raw"
    }
    fn plugin_type(&self) -> &str {
        "tls2raw"
    }
}

pub struct UnixDomainSocketPlugin {
    unix_path: String,
}

impl UnixDomainSocketPlugin {
    fn new(config: &ClientPluginConfig) -> Result<Self> {
        Ok(Self {
            unix_path: config
                .unix_path
                .clone()
                .unwrap_or_else(|| "/tmp/chagle.sock".to_string()),
        })
    }
}

impl ClientPlugin for UnixDomainSocketPlugin {
    fn name(&self) -> &str {
        "unix_domain_socket"
    }
    fn plugin_type(&self) -> &str {
        "unix_domain_socket"
    }
}

// ---------- Server Plugin (HTTP RPC) ----------

/// Server-side plugin that calls external HTTP endpoints
#[derive(Debug)]
pub struct ServerPlugin {
    pub name: String,
    pub addr: String,
    pub path: String,
    pub ops: Vec<String>,
    pub tls_verify: bool,
}

/// Operations that server plugins can intercept
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginOp {
    Login,
    NewProxy,
    CloseProxy,
    Ping,
    NewWorkConn,
    NewUserConn,
}

impl PluginOp {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Login" => Some(Self::Login),
            "NewProxy" => Some(Self::NewProxy),
            "CloseProxy" => Some(Self::CloseProxy),
            "Ping" => Some(Self::Ping),
            "NewWorkConn" => Some(Self::NewWorkConn),
            "NewUserConn" => Some(Self::NewUserConn),
            _ => None,
        }
    }
}

/// Response from a server plugin
#[derive(Debug, serde::Deserialize)]
pub struct PluginResponse {
    pub reject: bool,
    #[serde(default)]
    pub reject_msg: String,
    #[serde(default)]
    pub unchange: bool,
    pub content: Option<serde_json::Value>,
}

impl ServerPlugin {
    pub fn new(config: &crate::config::ServerPluginConfig) -> Self {
        Self {
            name: config.name.clone(),
            addr: config.addr.clone(),
            path: config.path.clone(),
            ops: config.ops.clone(),
            tls_verify: config.tls_verify,
        }
    }

    pub fn supports_op(&self, op: &str) -> bool {
        self.ops.iter().any(|o| o == op)
    }

    /// Call the plugin's HTTP endpoint
    pub async fn call(&self, op: &str, content: &serde_json::Value) -> Result<PluginResponse> {
        let _url = format!("http://{}{}", self.addr, self.path);

        let body = serde_json::json!({
            "version": "0.1.0",
            "op": op,
            "content": content,
        });

        // Simple HTTP POST using TCP
        let mut stream = TcpStream::connect(&self.addr).await?;
        let body_str = serde_json::to_string(&body)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.path,
            self.addr,
            body_str.len(),
            body_str
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        let response_str = String::from_utf8_lossy(&response);
        // Extract body after \r\n\r\n
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            let result: PluginResponse = serde_json::from_str(body)?;
            Ok(result)
        } else {
            anyhow::bail!("Invalid plugin response")
        }
    }
}
