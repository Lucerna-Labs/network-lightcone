//! LEARN-HOST-1 learner (path-lightcone/LEARN-HOST-1-PRECOMMIT.md). Unprivileged.
//!
//! Usage: pathlearn CAPTURE_DIR PACK_FILE
//!
//! Reads every finished `*.pcap` in CAPTURE_DIR (all but the newest, which the capture is still
//! writing), senses each packet into its path (direction from the cooked-capture packet type;
//! loopback skipped, as door one does not gate it), adds the de-duplicated paths to PACK_FILE
//! (role "host"), deletes each capture once read, and prints a readiness report.

use path_sense::{sense, Path, Sym, F_DPORT, F_ICMP, F_L4, F_SPORT};
use std::collections::BTreeSet;

const ROLE: &str = "host";
const LINKTYPE_SLL: u32 = 113;
const LINKTYPE_SLL2: u32 = 276;
const ARPHRD_LOOPBACK: u16 = 772;
const PACKET_OUTGOING: u8 = 4;

/// Packets of one capture file as (frame in SLL2 form, outbound), loopback skipped.
fn packets(bytes: &[u8]) -> Option<Vec<(Vec<u8>, bool)>> {
    if bytes.len() < 24 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != 0xa1b2_c3d4 && magic != 0xa1b2_3c4d {
        return None; // only little-endian classic pcap (what tcpdump writes here)
    }
    let link = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= bytes.len() {
        let cl = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().ok()?) as usize;
        off += 16;
        if off + cl > bytes.len() {
            break; // a final record cut short by a stop
        }
        let f = &bytes[off..off + cl];
        off += cl;
        match link {
            LINKTYPE_SLL2 if f.len() >= 20 => {
                if u16::from_be_bytes([f[8], f[9]]) == ARPHRD_LOOPBACK {
                    continue;
                }
                out.push((f.to_vec(), f[10] == PACKET_OUTGOING));
            }
            LINKTYPE_SLL if f.len() >= 16 => {
                if u16::from_be_bytes([f[2], f[3]]) == ARPHRD_LOOPBACK {
                    continue;
                }
                let mut g = Vec::with_capacity(20 + f.len() - 16);
                g.extend_from_slice(&f[14..16]); // EtherType
                g.extend_from_slice(&[0u8; 18]);
                g.extend_from_slice(&f[16..]);
                out.push((g, u16::from_be_bytes([f[0], f[1]]) == PACKET_OUTGOING as u16));
            }
            _ => {}
        }
    }
    Some(out)
}

fn has(p: &Path, f: u8, v: u128) -> bool {
    p.iter().any(|s| s.field == f && s.value == v)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (dir, pack_file) = (&a[1], &a[2]);
    let mut set: BTreeSet<Path> = std::fs::read_to_string(pack_file)
        .ok()
        .and_then(|t| path_pack::decode(&t))
        .filter(|p| p.role == ROLE)
        .map(|p| p.paths.into_iter().collect())
        .unwrap_or_default();
    let before = set.len();
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().map(|x| x == "pcap").unwrap_or(false)).collect();
    files.sort();
    let current = files.pop(); // the capture is still writing the newest file
    let (mut read, mut sensed, mut packets_seen) = (0, 0usize, 0usize);
    for f in &files {
        let Ok(bytes) = std::fs::read(f) else { continue };
        if let Some(ps) = packets(&bytes) {
            for (frame, outbound) in ps {
                packets_seen += 1;
                if let Some(p) = sense(&frame, outbound) {
                    sensed += 1;
                    set.insert(p);
                }
            }
            read += 1;
            let _ = std::fs::remove_file(f); // only paths remain on disk
        }
    }
    let paths: Vec<Path> = set.into_iter().collect();
    let tmp = format!("{pack_file}.tmp");
    std::fs::write(&tmp, path_pack::encode(ROLE, &paths)).unwrap();
    std::fs::rename(&tmp, pack_file).unwrap();
    println!("read {read} finished capture(s) (left the current one: {}), {packets_seen} packets, {sensed} with a path", current.map(|c| c.display().to_string()).unwrap_or("none".into()));
    println!("host pack: {} distinct paths (was {before}) -> {pack_file}", paths.len());
    let port = |v: u128| paths.iter().any(|p| has(p, F_SPORT, v) || has(p, F_DPORT, v));
    let icmp6 = |t: u128| paths.iter().any(|p| has(p, F_L4, 58) && has(p, F_ICMP, t << 8));
    let checks = [
        ("DHCP (UDP 67/68)", paths.iter().any(|p| has(p, F_L4, 17) && (port(67) || port(68)) && (has(p, F_SPORT, 67) || has(p, F_DPORT, 67) || has(p, F_SPORT, 68) || has(p, F_DPORT, 68)))),
        ("DNS (port 53)", port(53)),
        ("IPv6 router solicitation (133)", icmp6(133)),
        ("IPv6 router advertisement (134)", icmp6(134)),
        ("IPv6 neighbour solicitation (135)", icmp6(135)),
        ("IPv6 neighbour advertisement (136)", icmp6(136)),
    ];
    println!("readiness for enforcement:");
    for (name, ok) in checks {
        println!("  {} {name}", if ok { "present" } else { "MISSING" });
    }
    let _ = Sym { field: 0, value: 0 };
}
