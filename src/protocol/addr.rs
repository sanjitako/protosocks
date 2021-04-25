use core::cmp::min;
use core::convert::TryFrom;
use core::fmt;

use smolsocket::{port_from_bytes, port_to_bytes, SocketAddr};

use crate::field::Field;

use super::{Atyp, CrateResult, Error};

/// includes length of domain if addr is domain:port
#[inline]
pub(crate) fn addr_len(atyp: Atyp, domain_len: Option<u8>) -> usize {
    match atyp {
        Atyp::V4 => 4,
        Atyp::V6 => 16,
        Atyp::Domain => 1 + domain_len.unwrap() as usize,
    }
}

#[inline]
pub(crate) fn field_addr(start: usize, addr_len: usize) -> Field {
    start..start + addr_len
}

#[inline]
pub(crate) fn field_port(start: usize, addr_len: usize) -> Field {
    let pos_port = field_addr(start, addr_len).end;
    pos_port..pos_port + 2
}

#[inline]
pub(crate) fn field_socks_addr(start: usize, addr_len: usize) -> Field {
    field_addr(start + 1, addr_len).start - 1..field_port(start + 1, addr_len).end
}

#[derive(Debug, PartialEq, Clone)]
pub struct HasAddr<T: AsRef<[u8]>> {
    pub field_atyp: usize,
    pub buffer: T,
}

impl<T: AsRef<[u8]>> HasAddr<T> {
    /// Imbue a raw octet buffer with HasAddr packet structure.
    pub fn new_unchecked(field_atyp: usize, buffer: T) -> HasAddr<T> {
        HasAddr { field_atyp, buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_addr_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_addr_len]: #method.check_addr_len
    pub fn new_checked(field_atyp: usize, buffer: T) -> CrateResult<HasAddr<T>> {
        let packet = Self::new_unchecked(field_atyp, buffer);
        packet.check_addr_len()?;
        Ok(packet)
    }

    #[inline]
    fn addr_len(&self) -> usize {
        let atyp = self.parse_atyp().expect("atyp should be valid");
        if atyp == Atyp::Domain {
            let domain_len = self.buffer.as_ref()[self.field_addr_start()];
            addr_len(atyp, Some(domain_len))
        } else {
            addr_len(atyp, None)
        }
    }

    #[inline]
    fn field_addr(&self) -> Field {
        let addr_len = self.addr_len();
        field_addr(self.field_addr_start(), addr_len)
    }

    #[inline]
    pub(crate) fn field_port(&self) -> Field {
        let addr_len = self.addr_len();
        field_port(self.field_addr_start(), addr_len)
    }

    #[inline]
    fn field_socks_addr(&self) -> Field {
        let addr_len = self.addr_len();
        field_socks_addr(self.field_atyp, addr_len)
    }

    #[inline]
    fn field_addr_start(&self) -> usize {
        self.field_atyp + 1
    }

    /// len to the end of port (end of field port)
    #[inline]
    pub(crate) fn len_to_port(&self) -> usize {
        self.field_port().end
    }

    /// Return the atyp.
    #[inline]
    pub fn atyp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[self.field_atyp]
    }

    /// Return the dst port of request or bnd port of reply (unchecked).
    #[inline]
    pub fn port(&self) -> u16 {
        let field_port = self.field_port();
        let data = self.buffer.as_ref();
        let port_bytes = &data[field_port];
        port_from_bytes(port_bytes[0], port_bytes[1])
    }

    /// Return the atyp.
    #[inline]
    pub fn parse_atyp(&self) -> CrateResult<Atyp> {
        Atyp::try_from(self.atyp())
    }

    /// Check the length of socks addr.
    #[inline]
    pub fn check_addr_len(&self) -> CrateResult<()> {
        let len = self.buffer.as_ref().len();
        if len < self.field_addr_start() {
            return Err(Error::Truncated);
        }
        self.parse_atyp()?;
        if len < self.len_to_port() {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    pub fn take_buffer(self) -> T {
        self.buffer
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> HasAddr<&'a T> {
    /// Return a pointer to the addr (unchecked).
    #[inline]
    pub fn addr(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.field_addr()]
    }

    /// Return a pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr(&self) -> &'a [u8] {
        let field = self.field_socks_addr();
        let data = self.buffer.as_ref();
        &data[field]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HasAddr<T> {
    /// Set the atyp.
    #[inline]
    pub fn set_atyp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[self.field_atyp] = value;
    }

    /// Set the addr (unchecked).
    #[inline]
    pub fn set_addr(&mut self, value: &[u8]) {
        let atyp = self.atyp();
        let field = self.field_addr();
        let data = self.buffer.as_mut();
        let mut_slice = if atyp != Atyp::Domain as u8 {
            &mut data[field]
        } else {
            data[field.start] = value.len() as u8;
            &mut data[field.start + 1..field.end]
        };
        mut_slice.copy_from_slice(value);
    }

    /// Set the port (unchecked).
    #[inline]
    pub fn set_port(&mut self, value: u16) {
        let field = self.field_port();
        let data = self.buffer.as_mut();
        let mut_slice = &mut data[field];
        mut_slice.copy_from_slice(&port_to_bytes(value));
    }

    /// Set the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn set_socks_addr(&mut self, value: &[u8]) {
        let addr = Addr::try_from(value).expect("should be a valid addr");
        let field = field_socks_addr(self.field_atyp, addr.addr_len());
        let data = self.buffer.as_mut();
        let mut_slice = &mut data[field];
        mut_slice.copy_from_slice(value);
    }

    /// Return a mutable pointer to the addr (unchecked).
    #[inline]
    pub fn addr_mut(&mut self) -> &mut [u8] {
        let field = self.field_addr();
        let data = self.buffer.as_mut();
        &mut data[field]
    }

    /// Return a mutable pointer to the socks addr (atyp, addr, and port) (unchecked).
    #[inline]
    pub fn socks_addr_mut(&mut self) -> &mut [u8] {
        let field = self.field_socks_addr();
        let data = self.buffer.as_mut();
        &mut data[field]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Addr {
    SocketAddr(SocketAddr),
    DomainPort(String, u16),
}

impl Addr {
    pub fn new_domain(domain: &str, port: u16) -> Self {
        Addr::DomainPort(domain.to_string(), port)
    }

    pub fn new_socket(addr: SocketAddr) -> Self {
        Addr::SocketAddr(addr)
    }

    pub fn atyp(&self) -> Atyp {
        match self {
            #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
            Addr::SocketAddr(socket_addr) => match socket_addr {
                #[cfg(feature = "proto-ipv4")]
                SocketAddr::V4(_) => Atyp::V4,
                #[cfg(feature = "proto-ipv6")]
                SocketAddr::V6(_) => Atyp::V6,
            },
            Addr::DomainPort(_host, _port) => Atyp::Domain,
        }
    }

    pub fn addr_len(&self) -> usize {
        let atyp = self.atyp();
        match self {
            Addr::DomainPort(domain, _port) => {
                addr_len(atyp, Some(min(domain.as_bytes().len(), 255) as u8))
            }
            Addr::SocketAddr(_socket_addr) => addr_len(atyp, None),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Addr::DomainPort(_domain, port) => *port,
            Addr::SocketAddr(socket_addr) => socket_addr.port(),
        }
    }

    pub fn total_len(&self) -> usize {
        1 + self.addr_len() + 2
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = vec![0 as u8; self.total_len()];
        self.emmit(vec.as_mut_slice());
        vec
    }

    pub fn emmit(&self, bytes: &mut [u8]) {
        let total_len = self.total_len();
        bytes[0] = self.atyp() as u8;
        match self {
            #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
            Addr::SocketAddr(socket_addr) => {
                socket_addr.emmit(&mut bytes[1..total_len]);
            }
            Addr::DomainPort(domain, port) => {
                let domain_bytes = domain.as_bytes();
                let domain_len = min(domain_bytes.len(), 255);
                bytes[1] = domain_len as u8;
                bytes[2..2 + domain_bytes.len()].copy_from_slice(domain_bytes);
                bytes[total_len - 2..total_len].copy_from_slice(&port_to_bytes(*port));
            }
        }
    }
}

impl From<SocketAddr> for Addr {
    fn from(val: SocketAddr) -> Self {
        Addr::SocketAddr(val)
    }
}

impl TryFrom<&[u8]> for Addr {
    type Error = Error;

    fn try_from(value: &[u8]) -> CrateResult<Self> {
        let len = value.len();
        if len < 3 {
            Err(Error::Truncated)
        } else {
            let atyp = Atyp::try_from(value[0])?;
            let addr_len = if atyp == Atyp::Domain {
                addr_len(atyp, Some(value[1]))
            } else {
                addr_len(atyp, None)
            };
            let start_addr_port = 1;
            let field_port = field_port(start_addr_port, addr_len);
            let total_len = field_port.end;
            match len {
                l if l == total_len => {
                    let field_addr = field_addr(start_addr_port, addr_len);
                    match atyp {
                        #[cfg(feature = "proto-ipv4")]
                        Atyp::V4 => Ok(Addr::SocketAddr(SocketAddr::v4_from_bytes(
                            &value[field_addr.start..field_port.end],
                        )?)),
                        #[cfg(feature = "proto-ipv6")]
                        Atyp::V6 => Ok(Addr::SocketAddr(SocketAddr::v6_from_bytes(
                            &value[field_addr.start..field_port.end],
                        )?)),
                        Atyp::Domain => {
                            let domain = String::from_utf8_lossy(
                                &value[field_addr.start + 1..field_addr.end],
                            )
                                .to_string();
                            let port_bytes = &value[field_port];
                            let port = port_from_bytes(port_bytes[0], port_bytes[1]);
                            Ok(Addr::DomainPort(domain, port))
                        }
                        #[cfg(not(all(feature = "proto-ipv4", feature = "proto-ipv6")))]
                        _ => Err(Error::Malformed),
                    }
                }
                l if l < total_len => Err(Error::Truncated),
                _ => Err(Error::Malformed),
            }
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::SocketAddr(addr) => write!(f, "{}", addr),
            Addr::DomainPort(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}