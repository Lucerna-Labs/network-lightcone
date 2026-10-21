//! PATHGATE-1 orchestrator (path-lightcone/PATHGATE-1-PRECOMMIT.md). The PATHCONE-1 run-6 world
//! (context folding relative to the field) put in the kernel packet path as a fail-closed queue
//! verdict. Lab only: refuses to run outside a private user + network namespace without
//! PATHGATE_LAB=1. Every setting is here.
//!
//! Modes:
//!   gate EVIDENCE ROLE QUEUE SECONDS hold each packet, judge it, release or discard ("V hash pass ns")
//!   observe QUEUE SECONDS            release every packet, record it ("O hash"): the passage receipt
//!   inject EVIDENCE ROLE in|out IFACE DSTMAC SRCMAC pos|all MANIFEST   replay recorded packets
//!                                    (+ mutations): in = Ethernet frames onto the veth (PREROUTING),
//!                                    out = header-included raw IP sends (OUTPUT)
//!   report MANIFEST OBSERVED GATELOG compare kernel outcome with the offline verdict

use path_admit::admit;
use path_frame::held_path;
use path_inject::{Injector, RawIp};
use path_queue::{KernelDisposition, PacketQueue};
use path_sense::{sense, Path, Sym, F_DPORT, F_DST, F_SPORT, F_SRC};
use path_world::{CtxFold, World};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const FOLD: CtxFold = CtxFold { min_distinct: 3, ephemeral_fraction: 0.8, ephemeral_below: 3, relative_to_field: true };
const TRAIN_ATTEMPTS: u32 = 6;
const QUEUE_CAPACITY: u32 = 1024;
const SEND_GAP: Duration = Duration::from_micros(300);

struct Rec {
    outbound: bool,
    frame: Vec<u8>,
    case: Option<(String, u32)>,
    interface: String,
    truncated: bool,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let k = format!("\"{key}\": \"");
    let i = line.find(&k)? + k.len();
    let j = line[i..].find('"')? + i;
    Some(&line[i..j])
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

fn read_jsonl(path: &str) -> Vec<Rec> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter_map(|l| {
            let outbound = field(l, "direction")? == "out";
            let frame = hex(field(l, "captured_frame_hex")?);
            let case = l.find("\"case_ids\": [").and_then(|i| {
                let rest = &l[i + 13..];
                let body = &rest[..rest.find(']')?];
                let first = body.split(',').next()?.trim().trim_matches('"');
                let (name, n) = first.rsplit_once(':')?;
                Some((name.to_string(), n.parse().ok()?))
            });
            let interface = field(l, "interface").unwrap_or("").to_string();
            let truncated = !l.contains("\"truncated\": false");
            Some(Rec { outbound, frame, case, interface, truncated })
        })
        .collect()
}

/// Packet identity: FNV-1a over the bytes, with the IPv4 ID and header checksum skipped (the kernel
/// may fill both in for a header-included send).
fn fnv(b: &[u8]) -> u64 {
    let v4 = b.first().map(|x| x >> 4) == Some(4);
    b.iter().enumerate().filter(|(i, _)| !(v4 && matches!(i, 4 | 5 | 10 | 11))).fold(0xcbf2_9ce4_8422_2325u64, |h, (_, &x)| (h ^ x as u64).wrapping_mul(0x100_0000_01b3))
}

fn get(p: &Path, f: u8) -> Option<(usize, u128)> {
    p.iter().position(|s| s.field == f).map(|i| (i, p[i].value))
}

/// The world, exactly as PATHCONE-1 run 6 trains it for this role.
struct Worlds {
    allow: World,
    deny: World,
    untrained_port: u128,
}

fn set_at(p: &Path, i: usize, v: u128) -> Path {
    let mut q = p.clone();
    q[i].value = v;
    q
}

fn train(ev: &str, role: &str) -> (Worlds, Vec<Rec>) {
    let io = format!("{ev}/lightcone-vm-io-20261001");
    let healthy = read_jsonl(&format!("{io}/healthy-{role}-packets.jsonl"));
    let mut held = Vec::new();
    let mut train_paths = Vec::new();
    for r in healthy {
        if r.case.as_ref().map(|c| c.1 < TRAIN_ATTEMPTS).unwrap_or(true) {
            if let Some(p) = sense(&r.frame, r.outbound) {
                train_paths.push(p);
            }
        } else {
            held.push(r);
        }
    }
    for arm in ["quarantined", "kernel_recovered"] {
        held.extend(read_jsonl(&format!("{io}/{arm}-{role}-packets.jsonl")));
    }
    let seen: std::collections::HashSet<Sym> = train_paths.iter().flatten().copied().collect();
    let untrained_port = (40000u128..).find(|v| !seen.contains(&Sym { field: F_DPORT, value: *v }) && !seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap();
    let allow = World::train_context(&train_paths, FOLD);
    let deny_train: Vec<Path> = train_paths.iter().filter_map(|p| port_mutation(p, &allow, untrained_port)).collect();
    let deny = World::train(&deny_train, None);
    (Worlds { allow, deny, untrained_port }, held)
}

fn exact_index(p: &Path, w: &World, f: u8) -> Option<usize> {
    let trace = w.match_trace(p)?;
    get(p, f).map(|x| x.0).filter(|&i| trace[i])
}

fn port_mutation(p: &Path, w: &World, port: u128) -> Option<Path> {
    exact_index(p, w, F_DPORT).or_else(|| exact_index(p, w, F_SPORT)).map(|i| set_at(p, i, port))
}

fn ipv4_checksum(ip: &mut [u8]) {
    let ihl = (ip[0] & 0x0f) as usize * 4;
    ip[10] = 0;
    ip[11] = 0;
    let mut sum: u32 = (0..ihl / 2).map(|i| u16::from_be_bytes([ip[2 * i], ip[2 * i + 1]]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

/// Byte-level mutations of a bare IP packet, mirroring PATHCONE-1 run 3's exact-field classes.
fn mutate(ip: &[u8], w: &Worlds, class: usize, hook: u8) -> Option<Vec<u8>> {
    let p = held_path(ip, hook)?;
    let v4 = ip[0] >> 4 == 4;
    let (l4, proto_at) = if v4 { ((ip[0] & 0x0f) as usize * 4, 9) } else { (40, 6) };
    let proto = ip[proto_at];
    let mut m = ip.to_vec();
    match class {
        0 => {
            if !matches!(proto, 6 | 17) {
                return None;
            }
            let port = (w.untrained_port as u16).to_be_bytes();
            if exact_index(&p, &w.allow, F_DPORT).is_some() {
                m[l4 + 2..l4 + 4].copy_from_slice(&port);
            } else if exact_index(&p, &w.allow, F_SPORT).is_some() {
                m[l4..l4 + 2].copy_from_slice(&port);
            } else {
                return None;
            }
        }
        1 => {
            let (src, dst, new): ((usize, usize), (usize, usize), Vec<u8>) = if v4 {
                ((12, 16), (16, 20), vec![0xcb, 0x00, 0x71, 0xfa])
            } else {
                ((8, 24), (24, 40), 0x2001_0db8_0000_0000_0000_0000_0000_0badu128.to_be_bytes().to_vec())
            };
            let (a, b) = if exact_index(&p, &w.allow, F_SRC).is_some() {
                src
            } else if exact_index(&p, &w.allow, F_DST).is_some() {
                dst
            } else {
                return None;
            };
            m[a..b].copy_from_slice(&new);
        }
        _ => {
            m[proto_at] = match proto {
                17 => 6,
                6 => 17,
                _ => return None,
            };
        }
    }
    if v4 {
        ipv4_checksum(&mut m);
    }
    Some(m)
}

fn lab_only() {
    let same = |ns: &str| std::fs::read_link(format!("/proc/self/ns/{ns}")).ok() == std::fs::read_link(format!("/proc/1/ns/{ns}")).ok();
    if std::env::var("PATHGATE_LAB").as_deref() != Ok("1") || same("net") || same("user") {
        eprintln!("pathgate: refusing — lab only (PATHGATE_LAB=1 inside a private user + network namespace)");
        std::process::exit(2);
    }
}

fn mac(s: &str) -> Vec<u8> {
    s.split(':').map(|x| u8::from_str_radix(x, 16).expect("mac")).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("gate") => {
            lab_only();
            let (w, _) = train(&a[2], &a[3]);
            let mut q = PacketQueue::bind(a[4].parse().unwrap(), QUEUE_CAPACITY).expect("bind gate queue");
            println!("READY");
            let deadline = Instant::now() + Duration::from_secs(a[5].parse().unwrap());
            while Instant::now() < deadline {
                // Any transport error ends the reader: the kernel then drops everything held (fail-closed).
                let Some(pk) = q.receive(Duration::from_millis(50)).expect("receive") else { continue };
                let t = Instant::now();
                let path = held_path(pk.bytes(), pk.hook);
                let pass = admit(&w.allow, &w.deny, path.as_ref());
                let h = fnv(pk.bytes());
                q.finish(pk, if pass { KernelDisposition::Release } else { KernelDisposition::Discard }).expect("verdict");
                println!("V {h:016x} {} {}", pass as u8, t.elapsed().as_nanos());
            }
            println!("FINISHED");
        }
        Some("observe") => {
            lab_only();
            let mut q = PacketQueue::bind(a[2].parse().unwrap(), QUEUE_CAPACITY).expect("bind observer queue");
            println!("READY");
            let deadline = Instant::now() + Duration::from_secs(a[3].parse().unwrap());
            while Instant::now() < deadline {
                let Some(pk) = q.receive(Duration::from_millis(50)).expect("receive") else { continue };
                let h = fnv(pk.bytes());
                q.finish(pk, KernelDisposition::Release).expect("release");
                println!("O {h:016x}");
            }
            println!("FINISHED");
        }
        Some("inject") => {
            // inject EVIDENCE ROLE in|out IFACE DSTMAC SRCMAC pos|all MANIFEST
            lab_only();
            let (w, held) = train(&a[2], &a[3]);
            let outbound = a[4] == "out";
            let hook = if outbound { 3 } else { 0 };
            let link = if outbound { None } else { Some(Injector::open(&a[5]).expect("open injector")) };
            let raw = if outbound { Some(RawIp::open(&a[5]).expect("open raw sender")) } else { None };
            let (dst, src) = (mac(&a[6]), mac(&a[7]));
            let all = a[8] == "all";
            let mut manifest = String::new();
            let (mut sent, mut refused) = (0, 0);
            for r in held.iter().filter(|r| r.outbound == outbound && r.interface != "lo" && !r.truncated && r.frame.len() > 20) {
                let ether = [r.frame[0], r.frame[1]];
                if ether != [0x08, 0x00] && ether != [0x86, 0xdd] {
                    continue;
                }
                let ip = &r.frame[20..];
                let mut items = vec![("pos", ip.to_vec())];
                if all {
                    for (c, name) in ["neg-port", "neg-address", "neg-protocol"].iter().enumerate() {
                        if let Some(m) = mutate(ip, &w, c, hook) {
                            items.push((name, m));
                        }
                    }
                }
                for (class, bytes) in items {
                    let offline = admit(&w.allow, &w.deny, held_path(&bytes, hook).as_ref());
                    let res = match (&link, &raw) {
                        (Some(l), _) => {
                            let mut f = dst.clone();
                            f.extend_from_slice(&src);
                            f.extend_from_slice(&ether);
                            f.extend_from_slice(&bytes);
                            l.send(&f)
                        }
                        (_, Some(r)) => r.send(&bytes),
                        _ => unreachable!(),
                    };
                    // A send the kernel refuses (e.g. EPERM when the queue has no reader) did not pass:
                    // it stays in the manifest and the observer never sees it.
                    manifest.push_str(&format!("{:016x} {class} {}\n", fnv(&bytes), offline as u8));
                    match res {
                        Ok(()) => sent += 1,
                        Err(e) => {
                            println!("REFUSED {class} {:016x}: {e}", fnv(&bytes));
                            refused += 1;
                        }
                    }
                    std::thread::sleep(SEND_GAP);
                }
            }
            std::fs::write(&a[9], manifest).expect("manifest");
            println!("SENT {sent} REFUSED {refused}");
        }
        Some("report") => {
            let man = std::fs::read_to_string(&a[2]).unwrap();
            let obs = std::fs::read_to_string(&a[3]).unwrap();
            let mut seen: HashMap<&str, usize> = HashMap::new();
            for l in obs.lines().filter(|l| l.starts_with("O ")) {
                *seen.entry(&l[2..18]).or_default() += 1;
            }
            let mut by_class: std::collections::BTreeMap<&str, (usize, usize, usize)> = Default::default(); // (n, passed, agree)
            let rows: Vec<(&str, &str, bool)> = man.lines().map(|l| {
                let v: Vec<&str> = l.split(' ').collect();
                (v[0], v[1], v[2] == "1")
            }).collect();
            // Identical bytes have identical verdicts: consume observations per hash.
            let mut left = seen.clone();
            for (h, class, offline) in &rows {
                let passed = match left.get_mut(h) {
                    Some(n) if *n > 0 => {
                        *n -= 1;
                        true
                    }
                    _ => false,
                };
                let e = by_class.entry(class).or_default();
                e.0 += 1;
                e.1 += passed as usize;
                e.2 += (passed == *offline) as usize;
            }
            for (c, (n, p, ag)) in &by_class {
                println!("{c}: n {n}, kernel passed {p} ({:.4}), agreement with offline verdict {ag}/{n}", *p as f64 / *n as f64);
            }
            if a.len() > 4 {
                let gl = std::fs::read_to_string(&a[4]).unwrap();
                let mut ns: Vec<u64> = gl.lines().filter(|l| l.starts_with("V ")).filter_map(|l| l.split(' ').nth(3)?.parse().ok()).collect();
                ns.sort();
                if !ns.is_empty() {
                    println!("gate verdicts {}; latency median {} ns, p99 {} ns", ns.len(), ns[ns.len() / 2], ns[ns.len() * 99 / 100]);
                }
            }
        }
        _ => eprintln!("usage: pathgate gate|observe|inject|report ..."),
    }
}
