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
