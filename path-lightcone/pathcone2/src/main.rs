//! PATHCONE-1 run 2 orchestrator (path-lightcone/PATHCONE-1-PRECOMMIT.md, run 2): recurrence
//! folding (a position folds only when its values are mostly one-burst in time), mutations of
//! exactly-matched positions only, and the direction flip on end hosts only. Every setting is here.
//! Usage: pathcone2 IMPERIUM_EVIDENCE_DIR.

use path_admit::admit;
use path_sense::{sense, Path, Sym, F_DIR, F_DPORT, F_DST, F_L4, F_SPORT, F_SRC, F_TCPF};
use path_world::{RecurFold, World};
use std::collections::{BTreeMap, HashMap};

const FOLD: RecurFold = RecurFold { min_distinct: 3, one_burst_fraction: 0.8, window_ns: 1_000_000_000 };
const TRAIN_ATTEMPTS: u32 = 6;
const ROLES: [&str; 3] = ["hub", "source", "receiver"];

struct Rec {
    outbound: bool,
    time: u64,
    frame: Vec<u8>,
    case: Option<(String, u32)>,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let k = format!("\"{key}\": \"");
    let i = line.find(&k)? + k.len();
    let j = line[i..].find('"')? + i;
    Some(&line[i..j])
}

fn number(line: &str, key: &str) -> Option<u64> {
    let k = format!("\"{key}\": ");
    let i = line.find(&k)? + k.len();
    let j = line[i..].find(|c: char| !c.is_ascii_digit())? + i;
    line[i..j].parse().ok()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

fn read_jsonl(path: &str) -> Vec<Rec> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter_map(|l| {
            let outbound = field(l, "direction")? == "out";
            let time = number(l, "time_ns")?;
            let frame = hex(field(l, "captured_frame_hex")?);
            let case = l.find("\"case_ids\": [").and_then(|i| {
                let rest = &l[i + 13..];
                let body = &rest[..rest.find(']')?];
                let first = body.split(',').next()?.trim().trim_matches('"');
                let (name, n) = first.rsplit_once(':')?;
                Some((name.to_string(), n.parse().ok()?))
            });
            Some(Rec { outbound, time, frame, case })
        })
        .collect()
}

fn read_pcap(path: &str) -> Vec<Rec> {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= b.len() {
        let cl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16;
        let f = b[off..off + cl].to_vec();
        off += cl;
        out.push(Rec { outbound: f.get(10) == Some(&4), time: 0, frame: f, case: None });
    }
    out
}

fn get(p: &Path, f: u8) -> Option<(usize, u128)> {
    p.iter().position(|s| s.field == f).map(|i| (i, p[i].value))
}

fn set_at(p: &Path, i: usize, v: u128) -> Path {
    let mut q = p.clone();
    q[i].value = v;
    q
}

/// Exact-position mutations: (a) a port, (b) an address, (c) the protocol swap, (d) the direction.
fn mutations(p: &Path, w: &World, end_host: bool) -> [Option<Path>; 4] {
    let Some(trace) = w.match_trace(p) else { return [None, None, None, None] };
    let untrained_port = (40000u128..).find(|v| !w.seen.contains(&Sym { field: F_DPORT, value: *v }) && !w.seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap();
    let exact = |f: u8| get(p, f).filter(|(i, _)| trace[*i]);
    let a = exact(F_DPORT).or_else(|| exact(F_SPORT)).map(|(i, _)| set_at(p, i, untrained_port));
    let b = exact(F_SRC).or_else(|| exact(F_DST)).map(|(i, v)| set_at(p, i, if v > u32::MAX as u128 { 0x2001_0db8_0000_0000_0000_0000_0000_0badu128 } else { 0xcb00_71fa }));
    let c = match get(p, F_L4) {
        Some((i, 17)) => Some(set_at(p, i, 6)),
        Some((i, 6)) => Some(set_at(p, i, 17)),
        _ => None,
    };
    let d = if end_host { get(p, F_DIR).map(|(i, x)| set_at(p, i, 1 - x)) } else { None };
    [a, b, c, d]
}

fn rate(xs: &[bool]) -> f64 {
    xs.iter().filter(|&&x| x).count() as f64 / xs.len().max(1) as f64
}

fn main() {
    let ev = std::env::args().nth(1).expect("usage: pathcone2 IMPERIUM_EVIDENCE_DIR");
    let io = format!("{ev}/lightcone-vm-io-20261001");
    println!("PATHCONE-1 run 2: recurrence folding {FOLD:?}; train attempts < {TRAIN_ATTEMPTS}");
    let empty = World::default();
    let (mut p1, mut p3, mut p4, mut p8) = (true, true, true, true);
    let mut p5 = Vec::new();
    let mut deny_harm = 0usize;
    let mut bench = Vec::new();
    let mut receiver_world = None;
    for role in ROLES {
        let end_host = role != "hub";
        let healthy = read_jsonl(&format!("{io}/healthy-{role}-packets.jsonl"));
        let (train, mut held): (Vec<&Rec>, Vec<&Rec>) = healthy.iter().partition(|r| r.case.as_ref().map(|c| c.1 < TRAIN_ATTEMPTS).unwrap_or(true));
        let others: Vec<Rec> = ["quarantined", "kernel_recovered"].iter().flat_map(|arm| read_jsonl(&format!("{io}/{arm}-{role}-packets.jsonl"))).collect();
        held.extend(others.iter());
        let train_timed: Vec<(Path, u64)> = train.iter().filter_map(|r| sense(&r.frame, r.outbound).map(|p| (p, r.time))).collect();
        let train_paths: Vec<Path> = train_timed.iter().map(|x| x.0.clone()).collect();
        let held_paths: Vec<Option<Path>> = held.iter().map(|r| sense(&r.frame, r.outbound)).collect();
        let allow = World::train_timed(&train_timed, FOLD);
        let strict = World::train(&train_paths, None);
        let folded: BTreeMap<u8, usize> = allow.folded_fields();
        let pass: Vec<bool> = held_paths.iter().map(|p| admit(&allow, &empty, p.as_ref())).collect();
        let pass_strict = rate(&held_paths.iter().map(|p| admit(&strict, &empty, p.as_ref())).collect::<Vec<_>>());
        println!("[{role}] train {} ({} folds; wildcards per field {folded:?}); held-out legitimate {}: pass {:.4} (no folding {:.4})", train_paths.len(), allow.folds, held_paths.len(), rate(&pass), pass_strict);
        let misses: HashMap<String, usize> = held.iter().zip(&pass).filter(|(_, &ok)| !ok).fold(HashMap::new(), |mut m, (r, _)| {
            *m.entry(r.case.as_ref().map(|c| c.0.clone()).unwrap_or_else(|| "background".into())).or_default() += 1;
            m
        });
        if !misses.is_empty() {
            println!("   held-out misses by case: {misses:?}");
            if std::env::var_os("PATHCONE_DIAG").is_some() {
                let mut shapes: HashMap<Vec<(u8, u128)>, usize> = HashMap::new();
                for (r, ok) in held.iter().zip(&pass) {
                    if !ok {
                        if let Some(p) = sense(&r.frame, r.outbound) {
                            // Shape: direction, link, L4 and the ports/ICMP; addresses kept (they are the question).
                            *shapes.entry(p.iter().map(|s| (s.field, s.value)).collect()).or_default() += 1;
                        }
                    }
                }
                let mut v: Vec<_> = shapes.into_iter().collect();
                v.sort_by(|a, b| b.1.cmp(&a.1));
                for (sh, n) in v.iter().take(6) {
                    println!("   [diag] missed x{n}: {sh:?}");
                }
            }
        }
        p1 &= rate(&pass) >= 0.98;
        p5.push(rate(&pass) - pass_strict);
        p8 &= !folded.contains_key(&F_TCPF) && !folded.contains_key(&F_SRC) && !folded.contains_key(&F_DST);
        let mut cls = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for p in held_paths.iter().flatten() {
            for (i, m) in mutations(p, &allow, end_host).into_iter().enumerate() {
                if let Some(m) = m {
                    cls[i].push(!admit(&allow, &empty, Some(&m)));
                }
            }
        }
        let names = ["exact port", "exact address", "protocol swap", "direction flip (end hosts)"];
        println!("   mutations dropped: {}", (0..4).map(|i| format!("{} {:.4} (n {})", names[i], rate(&cls[i]), cls[i].len())).collect::<Vec<_>>().join(", "));
        p3 &= cls.iter().filter(|c| !c.is_empty()).all(|c| rate(c) >= 0.99);
        p4 &= held_paths.iter().all(|p| !admit(&World::default(), &empty, p.as_ref()));
        p4 &= held.iter().filter(|r| r.frame.len() > 30).all(|r| !admit(&allow, &empty, sense(&r.frame[..30], r.outbound).as_ref()));
        // P6: the deny world from the corrected class (a) of the training paths.
        let deny_train: Vec<Path> = train_paths.iter().filter_map(|p| mutations(p, &allow, end_host)[0].clone()).collect();
        let deny = World::train(&deny_train, None);
        let harmed = held_paths.iter().flatten().filter(|p| allow.matches(p) && deny.matches(p)).count();
        let held_a: Vec<Path> = held_paths.iter().flatten().filter_map(|p| mutations(p, &allow, end_host)[0].clone()).collect();
        let deny_catches = held_a.iter().filter(|m| deny.matches(m)).count();
        println!("   deny world ({} paths): catches {deny_catches} of {} held-out class (a); legitimate packets it would wrongly drop: {harmed}", deny_train.len(), held_a.len());
        deny_harm += harmed;
        if role == "receiver" {
            receiver_world = Some(allow.clone());
        }
        bench.push((allow, held_paths.into_iter().flatten().collect::<Vec<_>>()));
    }
    let probes = read_pcap(&format!("{ev}/lightcone-vm-20260930-phase1/receiver/control/mesh.pcap"));
    let rw = receiver_world.unwrap();
    let p2: Vec<bool> = probes.iter().map(|r| !admit(&rw, &empty, sense(&r.frame, r.outbound).as_ref())).collect();
    println!("P2 real negative (phase-1 undeclared UDP probe): dropped {p2:?}");
    if std::env::var_os("PATHCONE_DIAG").is_some() {
        for r in &probes {
            let p = sense(&r.frame, r.outbound).unwrap();
            println!("   [diag] probe path {:?}", p.iter().map(|s| (s.field, s.value)).collect::<Vec<_>>());
            println!("   [diag] matched exactly (true) or by wildcard (false): {:?}", rw.match_trace(&p));
        }
    }
    let (w, ps) = &bench[0];
    let t = std::time::Instant::now();
    let mut n = 0u64;
    while n < 3_000_000 {
        for p in ps {
            std::hint::black_box(admit(w, &empty, Some(p)));
            n += 1;
        }
    }
    let per_s = n as f64 / t.elapsed().as_secs_f64();
    println!("P7 speed: {per_s:.0} admissions per second (one thread)");
    let v = [
        ("P1 trained paths pass (>= 0.98 every role)", p1),
        ("P2 the real negative is stopped", !p2.is_empty() && p2.iter().all(|&x| x)),
        ("P3 exact-position mutations stopped (each class >= 0.99)", p3),
        ("P4 fail-closed", p4),
        ("P5 folding load-bearing (>= 0.2 gain)", p5.iter().all(|&g| g >= 0.2)),
        ("P6 the deny world harms no legitimate packet", deny_harm == 0),
        ("P7 >= 1,000,000 admissions per second", per_s >= 1e6),
        ("P8 no TCP-flag or address wildcards (over-folding repaired)", p8),
    ];
    println!();
    for (name, ok) in &v {
        println!("{} {name}", if *ok { "HOLDS " } else { "FAILS " });
    }
    println!("\n{} of {} hold", v.iter().filter(|x| x.1).count(), v.len());
}
