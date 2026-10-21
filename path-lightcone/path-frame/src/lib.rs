//! PATHGATE adapter (path-lightcone/PATHGATE-1-PRECOMMIT.md). The kernel queue hands over a bare IP
//! packet (no link header) and the netfilter hook it was held at. `path-sense` reads Linux cooked
//! captures (SLL2), so the adapter puts a 20-byte SLL2 shim in front: the EtherType from the IP
//! version nibble, the rest zero (sense reads nothing else of it). Direction: held at OUTPUT (3) or
//! POSTROUTING (4) is outbound; PREROUTING (0), INPUT (1) and FORWARD (2) are inbound.

use path_sense::{sense, Path};

/// The SLL2-shimmed frame of a bare IP packet, or None when it is not IPv4/IPv6.
pub fn shim(ip: &[u8]) -> Option<Vec<u8>> {
    let ether: u16 = match ip.first()? >> 4 {
        4 => 0x0800,
        6 => 0x86dd,
        _ => return None,
    };
    let mut f = Vec::with_capacity(20 + ip.len());
    f.extend_from_slice(&ether.to_be_bytes());
    f.extend_from_slice(&[0u8; 18]);
    f.extend_from_slice(ip);
    Some(f)
}

/// The path of a kernel-held packet.
pub fn held_path(ip: &[u8], hook: u8) -> Option<Path> {
    sense(&shim(ip)?, matches!(hook, 3 | 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_matches_a_captured_frame() {
        let mut ip = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip.extend_from_slice(&[0x13, 0x88, 0xb3, 0xaf, 0, 8, 0, 0]);
        let mut captured = vec![0x08, 0x00];
        captured.extend_from_slice(&[7u8; 18]); // other SLL2 header bytes differ; sense ignores them
        captured.extend_from_slice(&ip);
        assert_eq!(held_path(&ip, 0), sense(&captured, false));
        assert_eq!(held_path(&ip, 3), sense(&captured, true));
        assert!(held_path(&[0x15, 0, 0], 0).is_none());
    }
}
