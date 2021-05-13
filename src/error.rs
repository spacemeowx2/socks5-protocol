use crate::CommandReply;
use std::io;
use thiserror::Error;

/// Library level `Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid version.
    #[error("Invalid version: {0}")]
    InvalidVersion(u8),

    /// Too many methods. Max to 255.
    #[error("Too many methods")]
    TooManyMethods,

    /// Invalid handshake.
    #[error("Invalid handshake")]
    InvalidHandshake,

    /// Invalid command.
    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    /// Invalid command reply.
    #[error("Invalid command reply: {0}")]
    InvalidCommandReply(u8),

    /// Invalid command reply with error.
    #[error("Command reply with error: {0:?}")]
    CommandReply(CommandReply),

    /// Domain too long.
    #[error("Domain too long {0}")]
    DomainTooLong(usize),

    /// Invalid domain.
    #[error("Invalid domain {0:?}")]
    InvalidDomain(Vec<u8>),

    /// Invalid address type.
    #[error("Invalid address type {0}")]
    InvalidAddressType(u8),

    /// IO error.
    #[error("IO error: {0:?}")]
    Io(#[from] io::Error),
}

/// Library level `Result`.
pub type Result<T, E = Error> = ::std::result::Result<T, E>;

impl Error {
    /// Map `Error` to `std::io::Error`.
    pub fn to_io_err(self) -> io::Error {
        match self {
            Error::Io(e) => e,
            e => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}
