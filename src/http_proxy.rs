use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Parsed HTTP request info (first line + headers only)
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub version: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub raw_bytes: Vec<u8>,
}

/// Parse just enough of an HTTP request to extract routing information
pub fn parse_http_request(buf: &[u8]) -> Result<HttpRequestInfo> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req
        .parse(buf)
        .with_context(|| "Failed to parse HTTP request")?;

    let header_len = match status {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => bail!("Incomplete HTTP request"),
    };

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let version = format!("HTTP/1.{}", req.version.unwrap_or(1));

    let mut host = String::new();
    let mut parsed_headers = Vec::new();

    for h in req.headers.iter() {
        if h.name.is_empty() {
            break;
        }
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).to_string();
        if name.eq_ignore_ascii_case("Host") {
            host = value.clone();
        }
        parsed_headers.push((name, value));
    }

    Ok(HttpRequestInfo {
        method,
        path,
        version,
        host,
        headers: parsed_headers,
        raw_bytes: buf[..header_len].to_vec(),
    })
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello message
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2)
    if buf.len() < 5 {
        return None;
    }
    // Content type 22 = Handshake
    if buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }

    let handshake = &buf[5..5 + record_len];
    // Handshake type 1 = ClientHello
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }

    // Skip handshake header (4 bytes), client version (2), random (32)
    let mut pos = 4 + 2 + 32;
    if pos >= handshake.len() {
        return None;
    }

    // Session ID length
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    // Cipher suites length
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= handshake.len() {
        return None;
    }

    // Compression methods length
    let comp_methods_len = handshake[pos] as usize;
    pos += 1 + comp_methods_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end && pos + 4 <= handshake.len() {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if pos + 2 > handshake.len() {
                return None;
            }
            let sni_list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut sni_pos = pos + 2;
            let sni_end = sni_pos + sni_list_len;

            while sni_pos + 3 <= sni_end && sni_pos + 3 <= handshake.len() {
                let name_type = handshake[sni_pos];
                let name_len =
                    u16::from_be_bytes([handshake[sni_pos + 1], handshake[sni_pos + 2]]) as usize;
                sni_pos += 3;

                if name_type == 0x00 && sni_pos + name_len <= handshake.len() {
                    return String::from_utf8(handshake[sni_pos..sni_pos + name_len].to_vec()).ok();
                }
                sni_pos += name_len;
            }
        }

        pos += ext_len;
    }

    None
}

/// Route entry for HTTP vhost routing
#[derive(Debug, Clone)]
pub struct HttpRoute {
    pub service_name: String,
    pub custom_domains: Vec<String>,
    pub subdomain: Option<String>,
    pub locations: Vec<String>,
    pub host_header_rewrite: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<String>,
    pub request_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    pub route_by_http_user: Option<String>,
}

/// HTTP vhost router
#[derive(Debug)]
pub struct VhostRouter {
    routes: Vec<HttpRoute>,
    subdomain_host: Option<String>,
}

impl VhostRouter {
    pub fn new(subdomain_host: Option<String>) -> Self {
        Self {
            routes: Vec::new(),
            subdomain_host,
        }
    }

    pub fn add_route(&mut self, route: HttpRoute) {
        self.routes.push(route);
    }

    pub fn remove_route(&mut self, service_name: &str) {
        self.routes.retain(|r| r.service_name != service_name);
    }

    /// Find a matching route for a given host and path
    pub fn match_route(&self, host: &str, path: &str) -> Option<&HttpRoute> {
        // Strip port from host
        let host_without_port = host.split(':').next().unwrap_or(host);

        let mut best_match: Option<&HttpRoute> = None;
        let mut best_location_len = 0;

        for route in &self.routes {
            // Check custom domains
            let domain_match = route
                .custom_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(host_without_port));

            // Check subdomain
            let subdomain_match =
                if let (Some(sub), Some(host_suffix)) = (&route.subdomain, &self.subdomain_host) {
                    let expected = format!("{}.{}", sub, host_suffix);
                    expected.eq_ignore_ascii_case(host_without_port)
                } else {
                    false
                };

            if !domain_match && !subdomain_match {
                continue;
            }

            // Check locations (longest prefix match)
            if route.locations.is_empty() {
                // No location constraint - matches everything
                if best_match.is_none() || best_location_len == 0 {
                    best_match = Some(route);
                    best_location_len = 0;
                }
            } else {
                for loc in &route.locations {
                    if path.starts_with(loc.as_str()) && loc.len() > best_location_len {
                        best_match = Some(route);
                        best_location_len = loc.len();
                    }
                }
            }
        }

        best_match
    }
}

/// Rewrite HTTP request headers based on route configuration
pub fn rewrite_request(info: &HttpRequestInfo, route: &HttpRoute, client_addr: &str) -> Vec<u8> {
    let mut output = format!("{} {} {}\r\n", info.method, info.path, info.version);

    // Add/modify headers
    let mut host_written = false;
    let mut xff_written = false;

    for (name, value) in &info.headers {
        // Check if this header should be replaced by request_headers config
        if let Some(new_value) = route.request_headers.get(name) {
            output.push_str(&format!("{}: {}\r\n", name, new_value));
            continue;
        }

        if name.eq_ignore_ascii_case("Host") {
            if let Some(rewrite) = &route.host_header_rewrite {
                output.push_str(&format!("Host: {}\r\n", rewrite));
            } else {
                output.push_str(&format!("Host: {}\r\n", value));
            }
            host_written = true;
        } else if name.eq_ignore_ascii_case("X-Forwarded-For") {
            output.push_str(&format!("X-Forwarded-For: {}, {}\r\n", value, client_addr));
            xff_written = true;
        } else {
            output.push_str(&format!("{}: {}\r\n", name, value));
        }
    }

    // Add X-Forwarded-For if not already present
    if !xff_written {
        output.push_str(&format!("X-Forwarded-For: {}\r\n", client_addr));
    }

    // Add X-Real-IP
    output.push_str(&format!("X-Real-IP: {}\r\n", client_addr));

    // Add extra request headers from config
    for (name, value) in &route.request_headers {
        // Skip if already handled
        if info
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            continue;
        }
        output.push_str(&format!("{}: {}\r\n", name, value));
    }

    output.push_str("\r\n");
    output.into_bytes()
}

/// Read bytes from a connection until we have a complete HTTP request header
pub async fn read_http_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            bail!("Connection closed before HTTP header complete");
        }
        buf.extend_from_slice(&tmp[..n]);

        // Check for end of headers
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }

        if buf.len() > 8192 {
            bail!("HTTP header too large (>8KB)");
        }
    }
}

/// HTTP Basic Auth validation
pub fn validate_basic_auth(headers: &[(String, String)], user: &str, password: &str) -> bool {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("Authorization") {
            if let Some(encoded) = value.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_decode(encoded.trim()) {
                    let expected = format!("{}:{}", user, password);
                    return decoded == expected;
                }
            }
        }
    }
    false
}

fn base64_decode(input: &str) -> Result<String> {
    // Simple base64 decode (we have the base64 crate available)
    let bytes = base64_decode_bytes(input)?;
    String::from_utf8(bytes).with_context(|| "Invalid UTF-8 in base64 decoded string")
}

fn base64_decode_bytes(input: &str) -> Result<Vec<u8>> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = CHARS
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| anyhow::anyhow!("Invalid base64 character"))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

/// Send a 404 response
pub async fn send_404<W: AsyncWrite + Unpin>(
    writer: &mut W,
    custom_page: Option<&str>,
) -> Result<()> {
    let body = custom_page.unwrap_or("<html><body><h1>404 Not Found</h1></body></html>");
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Send a 401 response for basic auth
pub async fn send_401<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    let body = "<html><body><h1>401 Unauthorized</h1></body></html>";
    let response = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"chagle\"\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Send a 502 Bad Gateway response
pub async fn send_502<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    let body = "<html><body><h1>502 Bad Gateway</h1></body></html>";
    let response = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let req = b"GET /hello HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        let info = parse_http_request(req).unwrap();
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/hello");
        assert_eq!(info.host, "example.com");
    }

    #[test]
    fn test_vhost_router() {
        let mut router = VhostRouter::new(Some("example.com".to_string()));
        router.add_route(HttpRoute {
            service_name: "web".to_string(),
            custom_domains: vec!["web.example.com".to_string()],
            subdomain: None,
            locations: vec![],
            host_header_rewrite: None,
            http_user: None,
            http_password: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            route_by_http_user: None,
        });
        router.add_route(HttpRoute {
            service_name: "api".to_string(),
            custom_domains: vec![],
            subdomain: Some("api".to_string()),
            locations: vec!["/v1".to_string()],
            host_header_rewrite: None,
            http_user: None,
            http_password: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            route_by_http_user: None,
        });

        let route = router.match_route("web.example.com", "/");
        assert!(route.is_some());
        assert_eq!(route.unwrap().service_name, "web");

        let route = router.match_route("api.example.com", "/v1/users");
        assert!(route.is_some());
        assert_eq!(route.unwrap().service_name, "api");

        let route = router.match_route("unknown.example.com", "/");
        assert!(route.is_none());
    }

    #[test]
    fn test_basic_auth() {
        // "user:pass" in base64 is "dXNlcjpwYXNz"
        let headers = vec![(
            "Authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        )];
        assert!(validate_basic_auth(&headers, "user", "pass"));
        assert!(!validate_basic_auth(&headers, "user", "wrong"));
    }

    #[test]
    fn test_extract_sni() {
        // A minimal TLS ClientHello is complex to construct,
        // so just test that non-TLS data returns None
        assert_eq!(extract_sni(b"GET / HTTP/1.1"), None);
        assert_eq!(extract_sni(b""), None);
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01]), None);
    }
}
