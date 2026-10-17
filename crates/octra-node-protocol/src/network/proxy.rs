//! Optional local SOCKS5 transport. Native peer authentication runs unchanged
//! after CONNECT; a configured proxy never falls back to a direct connection.
use super::{endpoint::Endpoint, Error};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub fn validate(proxy: SocketAddr) -> Result<(), Error> {
    if !proxy.ip().is_loopback() || proxy.port() == 0 {
        return Err("P2P proxy must be a loopback endpoint with a nonzero port".into());
    }
    Ok(())
}

/// Open a TCP transport within ten seconds, including DNS and proxy negotiation.
pub async fn connect(endpoint: &Endpoint, proxy: Option<SocketAddr>) -> Result<TcpStream, Error> {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connect_inner(endpoint, proxy),
    )
    .await
    .map_err(|_| Error::from("P2P transport connect timeout"))?
}

async fn connect_inner(endpoint: &Endpoint, proxy: Option<SocketAddr>) -> Result<TcpStream, Error> {
    let host = std::str::from_utf8(&endpoint.host).map_err(|e| Error::from(e.to_string()))?;
    let Some(proxy) = proxy else {
        let address = tokio::net::lookup_host((host, endpoint.port))
            .await
            .map_err(|e| Error::from(e.to_string()))?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| Error::from("peer has no IPv4 address"))?;
        return TcpStream::connect(address)
            .await
            .map_err(|e| Error::from(e.to_string()));
    };
    validate(proxy)?;
    if host.is_empty() || host.len() > 255 || endpoint.port == 0 {
        return Err("invalid SOCKS5 peer endpoint".into());
    }
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    let exchange = async {
        stream.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        stream.read_exact(&mut method).await?;
        if method != [5, 0] {
            return Err(std::io::Error::other(
                "SOCKS5 proxy refused no-auth transport",
            ));
        }
        // Resolve at the proxy so host DNS and direct routes cannot become a
        // second egress path when the relay is unavailable.
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&endpoint.port.to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        if reply[..3] != [5, 0, 0] {
            return Err(std::io::Error::other("SOCKS5 CONNECT refused"));
        }
        let length = match reply[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(stream.read_u8().await?),
            _ => return Err(std::io::Error::other("invalid SOCKS5 address type")),
        };
        let mut bound = [0; 257];
        stream.read_exact(&mut bound[..length + 2]).await?;
        Ok::<_, std::io::Error>(())
    };
    exchange.await.map_err(|e| Error::from(e.to_string()))?;
    Ok(stream)
}

#[cfg(test)]
mod tests;
