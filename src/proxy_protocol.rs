use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// PROXY protocol v1 header
/// Format: PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n
pub fn proxy_protocol_v1_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let protocol = if src.is_ipv4() { "TCP4" } else { "TCP6" };
    format!(
        "PROXY {} {} {} {} {}\r\n",
        protocol,
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    )
    .into_bytes()
}

/// PROXY protocol v2 header (binary format)
/// Spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
pub fn proxy_protocol_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut header = Vec::new();

    // Signature (12 bytes)
    header.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);

    // Version (4 bits) | Command (4 bits): v2 PROXY
    header.push(0x21);

    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            // Address family (4 bits) | Protocol (4 bits): AF_INET | STREAM
            header.push(0x11);

            // Address length: 4+4+2+2 = 12
            header.extend_from_slice(&12u16.to_be_bytes());

            // Source address (4 bytes)
            header.extend_from_slice(&s.ip().octets());
            // Destination address (4 bytes)
            header.extend_from_slice(&d.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&s.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            // AF_INET6 | STREAM
            header.push(0x21);

            // Address length: 16+16+2+2 = 36
            header.extend_from_slice(&36u16.to_be_bytes());

            // Source address (16 bytes)
            header.extend_from_slice(&s.ip().octets());
            // Destination address (16 bytes)
            header.extend_from_slice(&d.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&s.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&d.port().to_be_bytes());
        }
        _ => {
            // Mixed address families: use LOCAL command
            header[12] = 0x20; // LOCAL
            header.push(0x00); // UNSPEC
            header.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    header
}

/// Write PROXY protocol header to a stream
pub async fn write_proxy_protocol_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: &str,
    src: SocketAddr,
    dst: SocketAddr,
) -> Result<()> {
    let header = match version {
        "v1" => proxy_protocol_v1_header(src, dst),
        "v2" => proxy_protocol_v2_header(src, dst),
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported proxy protocol version: {}",
                version
            ));
        }
    };
    writer.write_all(&header).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_v1_header_ipv4() {
        let src: SocketAddr = (Ipv4Addr::new(192, 168, 1, 1), 12345).into();
        let dst: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 80).into();
        let header = proxy_protocol_v1_header(src, dst);
        let expected = "PROXY TCP4 192.168.1.1 10.0.0.1 12345 80\r\n";
        assert_eq!(String::from_utf8(header).unwrap(), expected);
    }

    #[test]
    fn test_v1_header_ipv6() {
        let src: SocketAddr = (Ipv6Addr::LOCALHOST, 12345).into();
        let dst: SocketAddr = (Ipv6Addr::LOCALHOST, 80).into();
        let header = proxy_protocol_v1_header(src, dst);
        assert!(String::from_utf8(header).unwrap().starts_with("PROXY TCP6"));
    }

    #[test]
    fn test_v2_header_ipv4() {
        let src: SocketAddr = (Ipv4Addr::new(192, 168, 1, 1), 12345).into();
        let dst: SocketAddr = (Ipv4Addr::new(10, 0, 0, 1), 80).into();
        let header = proxy_protocol_v2_header(src, dst);
        // Signature check
        assert_eq!(
            &header[..12],
            &[
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
            ]
        );
        // Version + command
        assert_eq!(header[12], 0x21);
        // Total: 16 header + 12 address = 28
        assert_eq!(header.len(), 28);
    }
}
