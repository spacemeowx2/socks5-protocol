use crate::{
    Address, AuthRequest, AuthResponse, Command, CommandReply, CommandRequest, CommandResponse,
    Error, Result, Version,
};
use std::{io, net::SocketAddr};

/// Read `Self` from `io::Read` or write `Self` to `io::Write`.
pub trait FromIO {
    /// Read `Self` from `io::Read`.
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized;

    /// Write `Self` to `io::Write`.
    fn write_to(&self, writer: &mut impl io::Write) -> Result<()>;
}

impl FromIO for Version {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let version = &mut [0u8];
        reader.read_exact(version)?;
        match version[0] {
            5 => Ok(Version::V5),
            other => Err(Error::InvalidVersion(other)),
        }
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        let v = match self {
            Version::V5 => 5u8,
        };
        writer.write_all(&[v])?;
        Ok(())
    }
}

impl FromIO for AuthRequest {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let count = &mut [0u8];
        reader.read_exact(count)?;
        let mut methods = vec![0u8; count[0] as usize];
        reader.read_exact(&mut methods)?;

        Ok(AuthRequest(methods.into_iter().map(Into::into).collect()))
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        let count = self.0.len();
        if count > 255 {
            return Err(Error::TooManyMethods);
        }

        writer.write_all(&[count as u8])?;
        writer.write_all(
            &self
                .0
                .iter()
                .map(|i| Into::<u8>::into(*i))
                .collect::<Vec<_>>(),
        )?;

        Ok(())
    }
}

impl FromIO for AuthResponse {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let method = &mut [0u8];
        reader.read_exact(method)?;
        Ok(AuthResponse(method[0].into()))
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        writer.write_all(&[self.0.into()])?;
        Ok(())
    }
}

impl FromIO for CommandRequest {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let buf = &mut [0u8; 3];
        reader.read_exact(buf)?;
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

        let address = Address::read_from(reader)?;

        Ok(CommandRequest {
            command: cmd,
            address,
        })
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        let cmd = match self.command {
            Command::Connect => 1u8,
            Command::Bind => 2,
            Command::UdpAssociate => 3,
        };
        writer.write_all(&[0x05, cmd, 0x00])?;
        self.address.write_to(writer)?;
        Ok(())
    }
}

impl FromIO for CommandResponse {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let buf = &mut [0u8; 3];
        reader.read_exact(buf)?;
        if buf[0] != 5 {
            return Err(Error::InvalidVersion(buf[0]));
        }
        if buf[2] != 0 {
            return Err(Error::InvalidHandshake);
        }
        let reply = CommandReply::from_u8(buf[1])?;

        let address = Address::read_from(reader)?;

        if reply != CommandReply::Succeeded {
            return Err(Error::CommandReply(reply));
        }

        Ok(CommandResponse { reply, address })
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        writer.write_all(&[0x05, self.reply.to_u8(), 0x00])?;
        self.address.write_to(writer)?;
        Ok(())
    }
}

impl Address {
    fn read_port_from(reader: &mut impl io::Read) -> Result<u16> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        let port = u16::from_be_bytes(buf);
        Ok(port)
    }
    fn write_port_to(writer: &mut impl io::Write, port: u16) -> Result<()> {
        writer.write_all(&port.to_be_bytes())?;
        Ok(())
    }
}

impl FromIO for Address {
    fn read_from(reader: &mut impl io::Read) -> Result<Self>
    where
        Self: Sized,
    {
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp)?;

        Ok(match atyp[0] {
            1 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip)?;
                Address::SocketAddr(SocketAddr::new(ip.into(), Self::read_port_from(reader)?))
            }
            3 => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len)?;
                let len = len[0] as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain)?;

                let domain =
                    String::from_utf8(domain).map_err(|e| Error::InvalidDomain(e.into_bytes()))?;

                Address::Domain(domain, Self::read_port_from(reader)?)
            }
            4 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip)?;
                Address::SocketAddr(SocketAddr::new(ip.into(), Self::read_port_from(reader)?))
            }
            _ => return Err(Error::InvalidAddressType(atyp[0])),
        })
    }

    fn write_to(&self, writer: &mut impl io::Write) -> Result<()> {
        match self {
            Address::SocketAddr(SocketAddr::V4(addr)) => {
                writer.write_all(&[0x01])?;
                writer.write_all(&addr.ip().octets())?;
                Self::write_port_to(writer, addr.port())?;
            }
            Address::SocketAddr(SocketAddr::V6(addr)) => {
                writer.write_all(&[0x04])?;
                writer.write_all(&addr.ip().octets())?;
                Self::write_port_to(writer, addr.port())?;
            }
            Address::Domain(domain, port) => {
                if domain.len() >= 256 {
                    return Err(Error::DomainTooLong(domain.len()));
                }
                let header = [0x03, domain.len() as u8];
                writer.write_all(&header)?;
                writer.write_all(domain.as_bytes())?;
                Self::write_port_to(writer, *port)?;
            }
        };
        Ok(())
    }
}
