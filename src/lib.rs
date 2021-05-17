//! # Async tokio protocol
//!
//! `socks5-protocol` provides types that can be read from `AsyncRead` and write to `AsyncWrite`.
//!
//! You can create socks5 server or socks5 client using this library.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

use std::{
    convert::TryInto,
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use error::{Error, Result};

mod error;
#[cfg(feature = "sync")]
/// Sync version.
pub mod sync;

/// Version conatins one byte. In socks5, it should be `5`, other value will return `Error::InvalidVersion`.
///
/// ```
/// use std::io::Cursor;
/// use socks5_protocol::Version;
///
/// #[tokio::main]
/// async fn main() {
///    let mut buf = Cursor::new([5u8]);
///    let version = Version::read(&mut buf).await.unwrap();
///    assert_eq!(version, Version::V5);
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum Version {
    /// SOCKS Version 5
    V5,
}
impl Version {
    /// Read `Version` from AsyncRead.
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<Version> {
        let version = &mut [0u8];
        reader.read_exact(version).await?;
        match version[0] {
            5 => Ok(Version::V5),
            other => Err(Error::InvalidVersion(other)),
        }
    }
    /// Write `Version` to AsyncWrite.
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        let v = match self {
            Version::V5 => 5u8,
        };
        writer.write_all(&[v]).await?;
        Ok(())
    }
}

/// `AuthMethod` is defined in RFC 1928.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum AuthMethod {
    /// NO AUTHENTICATION REQUIRED. (`0x00`)
    Noauth,
    /// GSSAPI. (`0x01`)
    Gssapi,
    /// USERNAME/PASSWORD. (`0x02`)
    UsernamePassword,
    /// NO ACCEPTABLE METHODS. (`0xFF`)
    NoAcceptableMethod,
    /// Other values
    Other(u8),
}

impl From<u8> for AuthMethod {
    fn from(n: u8) -> Self {
        match n {
            0x00 => AuthMethod::Noauth,
            0x01 => AuthMethod::Gssapi,
            0x02 => AuthMethod::UsernamePassword,
            0xff => AuthMethod::NoAcceptableMethod,
            other => AuthMethod::Other(other),
        }
    }
}

impl Into<u8> for AuthMethod {
    fn into(self) -> u8 {
        match self {
            AuthMethod::Noauth => 0x00,
            AuthMethod::Gssapi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::NoAcceptableMethod => 0xff,
            AuthMethod::Other(other) => other,
        }
    }
}

/// `AuthRequest` message:
///
/// <pre><code>
/// +----------+----------+
/// | NMETHODS | METHODS  |
/// +----------+----------+
/// |    1     | 1 to 255 |
/// +----------+----------+
/// </code></pre>
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthRequest(pub Vec<AuthMethod>);

impl AuthRequest {
    /// Create an `AuthRequest`.
    pub fn new(methods: impl Into<Vec<AuthMethod>>) -> AuthRequest {
        AuthRequest(methods.into())
    }
    /// Read `AuthRequest` from AsyncRead.
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<AuthRequest> {
        let count = &mut [0u8];
        reader.read_exact(count).await?;
        let mut methods = vec![0u8; count[0] as usize];
        reader.read_exact(&mut methods).await?;

        Ok(AuthRequest(methods.into_iter().map(Into::into).collect()))
    }
    /// Write `AuthRequest` to AsyncWrite.
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        let count = self.0.len();
        if count > 255 {
            return Err(Error::TooManyMethods);
        }

        writer.write_all(&[count as u8]).await?;
        writer
            .write_all(
                &self
                    .0
                    .iter()
                    .map(|i| Into::<u8>::into(*i))
                    .collect::<Vec<_>>(),
            )
            .await?;

        Ok(())
    }
    /// Select one `AuthMethod` from give slice.
    pub fn select_from(&self, auth: &[AuthMethod]) -> AuthMethod {
        self.0
            .iter()
            .enumerate()
            .find(|(_, m)| auth.contains(*m))
            .map(|(v, _)| AuthMethod::from(v as u8))
            .unwrap_or(AuthMethod::NoAcceptableMethod)
    }
}

/// `AuthResponse` message:
///
/// <pre><code>
/// +--------+
/// | METHOD |
/// +--------+
/// |   1    |
/// +--------+
/// </code></pre>
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthResponse(AuthMethod);

impl AuthResponse {
    /// Create an `AuthMethod`.
    pub fn new(method: AuthMethod) -> AuthResponse {
        AuthResponse(method)
    }
    /// Read `AuthResponse` from AsyncRead.
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<AuthResponse> {
        let method = &mut [0u8];
        reader.read_exact(method).await?;
        Ok(AuthResponse(method[0].into()))
    }
    /// Write `AuthResponse` to AsyncWrite.
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        writer.write_all(&[self.0.into()]).await?;
        Ok(())
    }
    /// Get method.
    pub fn method(&self) -> AuthMethod {
        self.0
    }
}

/// `Command` type.
///
/// It has 3 commands: `Connect`, `Bind` and `UdpAssociate`.
#[derive(Debug)]
pub enum Command {
    /// Connect
    Connect,
    /// Bind
    Bind,
    /// Udp Associate
    UdpAssociate,
}

/// `CommandRequest` message:
///
/// <pre><code>
/// +-----+-------+------+----------+----------+
/// | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +-----+-------+------+----------+----------+
/// |  1  | X'00' |  1   | Variable |    2     |
/// +-----+-------+------+----------+----------+
/// </code></pre>
#[derive(Debug)]
pub struct CommandRequest {
    /// command (CMD).
    pub command: Command,
    /// Address (ATYP, DST.ADDR, DST.PORT).
    pub address: Address,
}

impl CommandRequest {
    /// Create a `CommandRequest` with `Connect` to `address`.
    pub fn connect(address: Address) -> CommandRequest {
        CommandRequest {
            command: Command::Connect,
            address,
        }
    }
    /// Create a `CommandRequest` with `UdpAssociate` to `address`.
    pub fn udp_associate(address: Address) -> CommandRequest {
        CommandRequest {
            command: Command::UdpAssociate,
            address,
        }
    }
    /// Read `CommandRequest` from `AsyncRead`.
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<CommandRequest> {
        let buf = &mut [0u8; 3];
        reader.read_exact(buf).await?;
        if buf[0] != 5 {
            return Err(Error::InvalidVersion(buf[0]));
        }
        if buf[2] != 0 {
            return Err(Error::InvalidHandshake);
        }
        let cmd = match buf[1] {
            1 => Command::Connect,
            2 => Command::Bind,
            3 => Command::UdpAssociate,
            _ => return Err(Error::InvalidCommand(buf[1])),
        };

        let address = Address::read(reader).await?;

        Ok(CommandRequest {
            command: cmd,
            address,
        })
    }
    /// Write `CommandRequest` to `AsyncWrite`.
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        let cmd = match self.command {
            Command::Connect => 1u8,
            Command::Bind => 2,
            Command::UdpAssociate => 3,
        };
        writer.write_all(&[0x05, cmd, 0x00]).await?;
        self.address.write(writer).await?;
        Ok(())
    }
}

/// Reply to `CommandRequest`
#[derive(Debug, PartialEq, PartialOrd)]
pub enum CommandReply {
    /// succeeded (0x00)
    Succeeded,
    /// general SOCKS server failure (0x01)
    GeneralSocksServerFailure,
    /// connection not allowed by ruleset (0x02)
    ConnectionNotAllowedByRuleset,
    /// Network unreachable (0x03)
    NetworkUnreachable,
    /// Host unreachable (0x04)
    HostUnreachable,
    /// Connection refused (0x05)
    ConnectionRefused,
    /// TTL expired (0x06)
    TtlExpired,
    /// Command not supported (0x07)
    CommandNotSupported,
    /// Address type not supported (0x08)
    AddressTypeNotSupported,
}

impl CommandReply {
    /// From `u8` to `CommandReply`.
    pub fn from_u8(n: u8) -> Result<CommandReply> {
        Ok(match n {
            0 => CommandReply::Succeeded,
            1 => CommandReply::GeneralSocksServerFailure,
            2 => CommandReply::ConnectionNotAllowedByRuleset,
            3 => CommandReply::NetworkUnreachable,
            4 => CommandReply::HostUnreachable,
            5 => CommandReply::ConnectionRefused,
            6 => CommandReply::TtlExpired,
            7 => CommandReply::CommandNotSupported,
            8 => CommandReply::AddressTypeNotSupported,
            _ => return Err(Error::InvalidCommandReply(n)),
        })
    }
    /// From `CommandReply` to `u8`.
    pub fn to_u8(&self) -> u8 {
        match self {
            CommandReply::Succeeded => 0,
            CommandReply::GeneralSocksServerFailure => 1,
            CommandReply::ConnectionNotAllowedByRuleset => 2,
            CommandReply::NetworkUnreachable => 3,
            CommandReply::HostUnreachable => 4,
            CommandReply::ConnectionRefused => 5,
            CommandReply::TtlExpired => 6,
            CommandReply::CommandNotSupported => 7,
            CommandReply::AddressTypeNotSupported => 8,
        }
    }
}

/// `CommandResponse` message:
///
/// <pre><code>
/// +-----+-------+------+----------+----------+
/// | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +-----+-------+------+----------+----------+
/// |  1  | X'00' |  1   | Variable |    2     |
/// +-----+-------+------+----------+----------+
/// </code></pre>
#[derive(Debug)]
pub struct CommandResponse {
    /// Reply (REP).
    pub reply: CommandReply,
    /// Address (ATYP, BND.ADDR, BND.PORT).
    pub address: Address,
}

impl CommandResponse {
    /// Create a success `CommandResponse` with bind `address`.
    pub fn success(address: Address) -> CommandResponse {
        CommandResponse {
            reply: CommandReply::Succeeded,
            address,
        }
    }
    /// Create a error `CommandResponse` with `reply`.
    pub fn reply_error(reply: CommandReply) -> CommandResponse {
        CommandResponse {
            reply,
            address: Default::default(),
        }
    }
    /// Create a error `CommandResponse` with any `io::error`.
    pub fn error(e: impl TryInto<io::Error>) -> CommandResponse {
        match e.try_into() {
            Ok(v) => {
                use io::ErrorKind;
                let reply = match v.kind() {
                    ErrorKind::ConnectionRefused => CommandReply::ConnectionRefused,
                    _ => CommandReply::GeneralSocksServerFailure,
                };
                CommandResponse {
                    reply,
                    address: Default::default(),
                }
            }
            Err(_) => CommandResponse {
                reply: CommandReply::GeneralSocksServerFailure,
                address: Default::default(),
            },
        }
    }
    /// Read `CommandResponse` from `AsyncRead`.
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<CommandResponse> {
        let buf = &mut [0u8; 3];
        reader.read_exact(buf).await?;
        if buf[0] != 5 {
            return Err(Error::InvalidVersion(buf[0]));
        }
        if buf[2] != 0 {
            return Err(Error::InvalidHandshake);
        }
        let reply = CommandReply::from_u8(buf[1])?;

        let address = Address::read(reader).await?;

        if reply != CommandReply::Succeeded {
            return Err(Error::CommandReply(reply));
        }

        Ok(CommandResponse { reply, address })
    }
    /// Write `CommandResponse` to `AsyncWrite`.
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<()> {
        writer.write_all(&[0x05, self.reply.to_u8(), 0x00]).await?;
        self.address.write(writer).await?;
        Ok(())
    }
}

/// Address type in socks5.
#[derive(Debug)]
pub enum Address {
    /// SocketAddr
    SocketAddr(SocketAddr),
    /// Domain
    Domain(String, u16),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::SocketAddr(s) => fmt::Display::fmt(s, f),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::SocketAddr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::SocketAddr(addr)
    }
}

fn host_to_address(host: &str, port: u16) -> Address {
    match str::parse::<IpAddr>(host) {
        Ok(ip) => {
            let addr = SocketAddr::new(ip, port);
            addr.into()
        }
        Err(_) => Address::Domain(host.to_string(), port),
    }
}
fn no_addr() -> io::Error {
    io::ErrorKind::AddrNotAvailable.into()
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ":");
        let host = parts.next().ok_or_else(no_addr)?;
        let port: u16 = parts
            .next()
            .ok_or_else(no_addr)?
            .parse()
            .map_err(|_| no_addr())?;
        Ok(host_to_address(host, port))
    }
}

impl Address {
    /// Convert `Address` to `SocketAddr`. If `Address` is a domain, return `std::io::ErrorKind::InvalidInput`
    pub fn to_socket_addr(self) -> Result<SocketAddr> {
        match self {
            Address::SocketAddr(s) => Ok(s),
            _ => Err(Error::Io(io::ErrorKind::InvalidInput.into())),
        }
    }
    async fn read_port<R>(mut reader: R) -> Result<u16>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        let port = u16::from_be_bytes(buf);
        Ok(port)
    }
    async fn write_port<W>(mut writer: W, port: u16) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(&port.to_be_bytes()).await?;
        Ok(())
    }
    /// Write `Address` to `AsyncWrite`.
    pub async fn write<W>(&self, mut writer: W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Address::SocketAddr(SocketAddr::V4(addr)) => {
                writer.write_all(&[0x01]).await?;
                writer.write_all(&addr.ip().octets()).await?;
                Self::write_port(writer, addr.port()).await?;
            }
            Address::SocketAddr(SocketAddr::V6(addr)) => {
                writer.write_all(&[0x04]).await?;
                writer.write_all(&addr.ip().octets()).await?;
                Self::write_port(writer, addr.port()).await?;
            }
            Address::Domain(domain, port) => {
                if domain.len() >= 256 {
                    return Err(Error::DomainTooLong(domain.len()));
                }
                let header = [0x03, domain.len() as u8];
                writer.write_all(&header).await?;
                writer.write_all(domain.as_bytes()).await?;
                Self::write_port(writer, *port).await?;
            }
        };
        Ok(())
    }
    /// Read `Address` from `AsyncRead`.
    pub async fn read<R>(mut reader: R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp).await?;

        Ok(match atyp[0] {
            1 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                Address::SocketAddr(SocketAddr::new(
                    ip.into(),
                    Self::read_port(&mut reader).await?,
                ))
            }
            3 => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len).await?;
                let len = len[0] as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await?;

                let domain =
                    String::from_utf8(domain).map_err(|e| Error::InvalidDomain(e.into_bytes()))?;

                Address::Domain(domain, Self::read_port(&mut reader).await?)
            }
            4 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                Address::SocketAddr(SocketAddr::new(
                    ip.into(),
                    Self::read_port(&mut reader).await?,
                ))
            }
            _ => return Err(Error::InvalidAddressType(atyp[0])),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_display() {
        let addr = Address::SocketAddr("1.2.3.4:56789".parse().unwrap());
        assert_eq!(addr.to_string(), "1.2.3.4:56789");

        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.to_string(), "example.com:80");
    }

    #[test]
    fn test_address_from_str() {
        let addr: Address = "1.2.3.4:56789".parse().unwrap();
        assert_eq!(addr.to_string(), "1.2.3.4:56789");

        let addr: Address = "example.com:80".parse().unwrap();
        assert_eq!(addr.to_string(), "example.com:80");

        let addr: Result<Address, _> = "example.com".parse();
        assert!(addr.is_err());
    }
}
