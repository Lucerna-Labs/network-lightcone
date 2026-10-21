//! The few Linux syscalls and constants the transport uses, declared here so the crate has no
//! dependencies (replacing the `libc` crate of the Imperium original). x86_64/aarch64 Linux values.
#![allow(non_camel_case_types)]

pub type c_int = i32;
pub type socklen_t = u32;

pub const AF_NETLINK: c_int = 16;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_CLOEXEC: c_int = 0o2000000;
pub const SOL_SOCKET: c_int = 1;
pub const SO_RCVBUF: c_int = 8;
pub const POLLIN: i16 = 0x1;
pub const POLLERR: i16 = 0x8;
pub const POLLHUP: i16 = 0x10;
pub const POLLNVAL: i16 = 0x20;
pub const MSG_TRUNC: c_int = 0x20;
#[cfg(test)]
pub const EPERM: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_nl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

#[repr(C)]
pub struct pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

extern "C" {
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const u8, len: socklen_t) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const u8, len: socklen_t) -> c_int;
    pub fn sendto(fd: c_int, buf: *const u8, len: usize, flags: c_int, addr: *const u8, alen: socklen_t) -> isize;
    pub fn recvfrom(fd: c_int, buf: *mut u8, len: usize, flags: c_int, addr: *mut u8, alen: *mut socklen_t) -> isize;
    pub fn poll(fds: *mut pollfd, n: u64, timeout: c_int) -> c_int;
}

pub fn zero_nl() -> sockaddr_nl {
    sockaddr_nl { nl_family: 0, nl_pad: 0, nl_pid: 0, nl_groups: 0 }
}
