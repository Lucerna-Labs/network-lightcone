//! PATHCONE run 3 (path-lightcone/PATHCONE-1-PRECOMMIT.md): **nibble expansion**. Every address and
//! port symbol becomes its 4-bit nibbles, most significant first, each its own trie position, so
//! the world can learn *which part* of a value varies (the interface half of a link-local address,
//! the low digits of ephemeral ports) while stable prefixes and service ports stay exact — CIDR-like
//! generalisation learned from traffic, never written. Borrowed law: positional notation (a number
//! is a path of digits, most significant first — the trie of a radix tree).
//!
//! Nibble positions get their own field numbers: source address 64+i, destination address 96+i,
//! source port 128+i, destination port 132+i. Address width follows the link symbol (IPv6: 32
//! nibbles; IPv4 and ARP: 8). Every other symbol passes through unchanged.

use path_sense::{Path, Sym, F_DPORT, F_DST, F_LINK, F_SPORT, F_SRC};

pub const N_SRC: u8 = 64;
pub const N_DST: u8 = 96;
pub const N_SPORT: u8 = 128;
pub const N_DPORT: u8 = 132;

/// The original field a (possibly nibble) field number belongs to.
pub fn origin(field: u8) -> u8 {
    match field {
        64..=95 => F_SRC,
        96..=127 => F_DST,
        128..=131 => F_SPORT,
        132..=135 => F_DPORT,
        f => f,
    }
}

fn push_nibbles(out: &mut Path, base: u8, value: u128, n: u32) {
    for i in 0..n {
        let shift = 4 * (n - 1 - i);
        out.push(Sym { field: base + i as u8, value: (value >> shift) & 0xf });
    }
}

/// The nibble-expanded path.
pub fn expand(p: &Path) -> Path {
    let v6 = p.iter().any(|s| s.field == F_LINK && s.value == 0x86dd);
    let addr = if v6 { 32 } else { 8 };
    let mut out = Vec::with_capacity(p.len() + 2 * addr as usize + 8);
    for s in p {
        match s.field {
            F_SRC => push_nibbles(&mut out, N_SRC, s.value, addr),
            F_DST => push_nibbles(&mut out, N_DST, s.value, addr),
            F_SPORT => push_nibbles(&mut out, N_SPORT, s.value, 4),
            F_DPORT => push_nibbles(&mut out, N_DPORT, s.value, 4),
            _ => out.push(*s),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_most_significant_first() {
        let p = vec![Sym { field: F_LINK, value: 0x0800 }, Sym { field: F_SRC, value: 0x0a00_0001 }, Sym { field: F_DPORT, value: 45999 }];
        let e = expand(&p);
        assert_eq!(e.len(), 1 + 8 + 4);
        assert_eq!(e[1], Sym { field: N_SRC, value: 0 });
        assert_eq!(e[2], Sym { field: N_SRC + 1, value: 0xa });
        assert_eq!(e[8], Sym { field: N_SRC + 7, value: 1 });
        assert_eq!(e[9..].iter().map(|s| s.value).collect::<Vec<_>>(), vec![0xb, 3, 0xa, 0xf]);
        assert!(e[9..].iter().all(|s| origin(s.field) == F_DPORT));
        let v6 = vec![Sym { field: F_LINK, value: 0x86dd }, Sym { field: F_DST, value: 0xff02 << 112 }];
        assert_eq!(expand(&v6).len(), 33);
    }
}
