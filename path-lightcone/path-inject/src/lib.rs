//! PATHGATE lab mechanism (path-lightcone/PATHGATE-1-PRECOMMIT.md): send raw Ethernet frames on one
//! named interface through an AF_PACKET socket. Used only inside the private lab namespace to replay
//! recorded packets byte-exact onto a veth. No judgment; zero dependencies (syscalls declared here).

use std::io;

#[repr(C)]
struct SockaddrLl {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, alen: u32) -> isize;
    fn close(fd: i32) -> i32;
    fn if_nametoindex(name: *const u8) -> u32;
}

pub struct Injector {
    fd: i32,
    ifindex: i32,
}

impl Injector {
    pub fn open(interface: &str) -> io::Result<Injector> {
        let mut name = interface.as_bytes().to_vec();
        name.push(0);
        // SAFETY: name is NUL-terminated and lives for the call.
        let ifindex = unsafe { if_nametoindex(name.as_ptr()) } as i32;
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain socket creation; the result is checked.
        let fd = unsafe { socket(17, 3 | 0o2000000, 0) }; // AF_PACKET, SOCK_RAW | CLOEXEC, protocol 0 (send only)
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Injector { fd, ifindex })
    }

    /// Send one complete Ethernet frame.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        let a = SockaddrLl { family: 17, protocol: 0, ifindex: self.ifindex, hatype: 0, pkttype: 0, halen: 6, addr: [0; 8] };
        // SAFETY: frame and address live for the call; sizes match.
        let n = unsafe { sendto(self.fd, frame.as_ptr(), frame.len(), 0, (&a as *const SockaddrLl).cast(), std::mem::size_of::<SockaddrLl>() as u32) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else if n as usize != frame.len() {
            Err(io::Error::new(io::ErrorKind::Other, "short packet send"))
        } else {
            Ok(())
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this injector.
        unsafe { close(self.fd) };
    }
}

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

extern "C" {
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, len: u32) -> i32;
}

/// Send complete IP packets (header included) from this host, bound to one interface, so they
/// cross the kernel's OUTPUT and POSTROUTING hooks.
pub struct RawIp {
    v4: i32,
    v6: i32,
    ifindex: u32,
}

impl RawIp {
    pub fn open(interface: &str) -> io::Result<RawIp> {
        let mut name = interface.as_bytes().to_vec();
        name.push(0);
        // SAFETY: name is NUL-terminated and lives for the call.
        let ifindex = unsafe { if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fds = [0i32; 2];
        for (i, family) in [2, 10].into_iter().enumerate() {
            // SAFETY: plain socket creation (AF_INET/AF_INET6, SOCK_RAW | CLOEXEC, IPPROTO_RAW).
            let fd = unsafe { socket(family, 3 | 0o2000000, 255) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: SO_BINDTODEVICE with the NUL-terminated name; sizes match.
            if unsafe { setsockopt(fd, 1, 25, name.as_ptr(), name.len() as u32) } < 0 {
                return Err(io::Error::last_os_error());
            }
            fds[i] = fd;
        }
        Ok(RawIp { v4: fds[0], v6: fds[1], ifindex })
    }

    /// Send one IP packet (IPv4 or IPv6, by its version nibble).
    pub fn send(&self, ip: &[u8]) -> io::Result<()> {
        let n = match ip.first().map(|b| b >> 4) {
            Some(4) if ip.len() >= 20 => {
                let a = SockaddrIn { family: 2, port: 0, addr: ip[16..20].try_into().unwrap(), zero: [0; 8] };
                // SAFETY: buffers live for the call; sizes match.
                unsafe { sendto(self.v4, ip.as_ptr(), ip.len(), 0, (&a as *const SockaddrIn).cast(), std::mem::size_of::<SockaddrIn>() as u32) }
            }
            Some(6) if ip.len() >= 40 => {
                let a = SockaddrIn6 { family: 10, port: 0, flowinfo: 0, addr: ip[24..40].try_into().unwrap(), scope_id: self.ifindex };
                // SAFETY: as above.
                unsafe { sendto(self.v6, ip.as_ptr(), ip.len(), 0, (&a as *const SockaddrIn6).cast(), std::mem::size_of::<SockaddrIn6>() as u32) }
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an IP packet")),
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for RawIp {
    fn drop(&mut self) {
        // SAFETY: both descriptors are owned by this sender.
        unsafe {
            close(self.v4);
            close(self.v6);
        }
    }
}
