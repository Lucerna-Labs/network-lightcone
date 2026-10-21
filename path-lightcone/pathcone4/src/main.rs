//! PATHCONE-1 run 4 orchestrator (path-lightcone/PATHCONE-1-PRECOMMIT.md, run 4): context-count
//! folding (a value following exactly one raw context is ephemeral), top-down, over raw paths.
//! Mutations apply only where the mutated field matched exactly. P2 withdrawn; the loopback control
//! flow (one training example) is reported, not predicted. Every setting is here.
//! Usage: pathcone4 IMPERIUM_EVIDENCE_DIR.

use path_admit::admit;
use path_sense::{sense, Path, Sym, F_DIR, F_DPORT, F_DST, F_L4, F_SPORT, F_SRC, F_TCPF};
use path_world::{CtxFold, World};
use std::collections::{BTreeMap, HashMap, HashSet};

const FOLD: CtxFold = CtxFold { min_distinct: 3, ephemeral_fraction: 0.8, ephemeral_below: 2, relative_to_field: false };
const TRAIN_ATTEMPTS: u32 = 6;
const ROLES: [&str; 3] = ["hub", "source", "receiver"];
const UNTRAINED_SERVICE_PROBE: u128 = 41000;

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

fn expand(p: &Path) -> Path {
    p.clone()
}

fn origin(f: u8) -> u8 {
    f
}

fn get(p: &Path, f: u8) -> Option<(usize, u128)> {
    p.iter().position(|s| s.field == f).map(|i| (i, p[i].value))
}

fn set_at(p: &Path, i: usize, v: u128) -> Path {
    let mut q = p.clone();
    q[i].value = v;
    q
}

/// Did every nibble (or the one symbol) of raw field `f` match exactly?
fn all_exact(e: &Path, trace: &[bool], f: u8) -> bool {
    let idx: Vec<usize> = (0..e.len()).filter(|&i| origin(e[i].field) == f).collect();
    !idx.is_empty() && idx.iter().all(|&i| trace[i])
}

/// Mutations of the raw path: (a) a port, (b) an address — only where every nibble matched
/// exactly — (c) the protocol swap, (d) the direction (end hosts).
fn mutations(p: &Path, w: &World, untrained_port: u128, end_host: bool) -> [Option<Path>; 4] {
    let e = expand(p);
    let Some(trace) = w.match_trace(&e) else { return [None, None, None, None] };
    let exact = |f: u8| get(p, f).filter(|_| all_exact(&e, &trace, f));
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

fn pass(w: &World, deny: &World, p: Option<&Path>) -> bool {
    admit(w, deny, p.map(expand).as_ref())
}

/// The (L4, port) service pairs a path names.
fn services(p: &Path) -> Vec<(u128, u128)> {
    let l4 = get(p, F_L4).map(|x| x.1).unwrap_or(0);
    [F_SPORT, F_DPORT].iter().filter_map(|&f| get(p, f).map(|x| (l4, x.1))).collect()
}

fn main() {
    let ev = std::env::args().nth(1).expect("usage: pathcone4 IMPERIUM_EVIDENCE_DIR");
    let diag = std::env::var_os("PATHCONE_DIAG").is_some();
    let io = format!("{ev}/lightcone-vm-io-20261001");
    println!("PATHCONE-1 run 4: context folding {FOLD:?}, top-down, raw paths; train attempts < {TRAIN_ATTEMPTS}");
    let empty = World::default();
    let (mut p1, mut _p1x, mut _p1b, mut p3, mut p4, mut p8) = (true, true, true, true, true, true);
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
        let raw_train: Vec<(Path, u64)> = train.iter().filter_map(|r| sense(&r.frame, r.outbound).map(|p| (p, r.time))).collect();
        let seen_raw: HashSet<Sym> = raw_train.iter().flat_map(|x| x.0.iter().copied()).collect();
        let trained_services: HashSet<(u128, u128)> = raw_train.iter().flat_map(|x| services(&x.0)).collect();
        let untrained_port = (40000u128..).find(|v| !seen_raw.contains(&Sym { field: F_DPORT, value: *v }) && !seen_raw.contains(&Sym { field: F_SPORT, value: *v })).unwrap();
        let train_exp: Vec<(Path, u64)> = raw_train.iter().map(|(p, t)| (expand(p), *t)).collect();
        let train_paths: Vec<Path> = train_exp.iter().map(|x| x.0.clone()).collect();
        let held_paths: Vec<Option<Path>> = held.iter().map(|r| sense(&r.frame, r.outbound)).collect();
        let allow = World::train_context(&train_paths, FOLD);
        let strict = World::train(&train_paths, None);
        let mut folded: BTreeMap<u8, usize> = BTreeMap::new();
        for (f, n) in allow.folded_fields() {
            *folded.entry(origin(f)).or_default() += n;
        }
        if diag {
            for (pre, sib) in allow.wild_contexts(F_TCPF) {
                println!("   [diag] TCP-flag wildcard after {} ({sib} exact siblings)", pre.iter().map(|s| if s.value == path_world::WILD { format!("{}:*", s.field) } else { format!("{}:{:x}", s.field, s.value) }).collect::<Vec<_>>().join(" "));
            }
        }
        let ok: Vec<bool> = held_paths.iter().map(|p| pass(&allow, &empty, p.as_ref())).collect();
        let pass_strict = rate(&held_paths.iter().map(|p| pass(&strict, &empty, p.as_ref())).collect::<Vec<_>>());
        let untrained_svc: Vec<bool> = held_paths.iter().map(|p| p.as_ref().map(|p| { let s = services(p); !s.is_empty() && s.iter().all(|x| !trained_services.contains(x)) }).unwrap_or(false)).collect();
        let ok_x: Vec<bool> = ok.iter().zip(&untrained_svc).filter(|(_, &u)| !u).map(|(&o, _)| o).collect();
        let probe41000: Vec<bool> = held_paths.iter().zip(&ok).filter(|(p, _)| p.as_ref().map(|p| services(p).contains(&(17, UNTRAINED_SERVICE_PROBE))).unwrap_or(false)).map(|(_, &o)| !o).collect();
        println!("[{role}] train {} ({} folds; wildcards per original field {folded:?})", train_paths.len(), allow.folds);
        println!("   held-out legitimate {}: pass {:.4} (no folding {:.4}); excluding {} untrained-service packets: pass {:.4}", held_paths.len(), rate(&ok), pass_strict, untrained_svc.iter().filter(|&&u| u).count(), rate(&ok_x));
        println!("   UDP {UNTRAINED_SERVICE_PROBE} (the tunnel port; trained service {}): held-out packets dropped {} of {}", trained_services.contains(&(17, UNTRAINED_SERVICE_PROBE)), probe41000.iter().filter(|&&x| x).count(), probe41000.len());
        let misses: HashMap<String, usize> = held.iter().zip(&ok).filter(|(_, &o)| !o).fold(HashMap::new(), |mut m, (r, _)| {
            *m.entry(r.case.as_ref().map(|c| c.0.clone()).unwrap_or_else(|| "background".into())).or_default() += 1;
            m
        });
        if !misses.is_empty() {
            println!("   held-out misses by case: {misses:?}");
            if diag {
                let mut shapes: HashMap<Vec<(u8, u128)>, usize> = HashMap::new();
                for ((p, o), u) in held_paths.iter().zip(&ok).zip(&untrained_svc) {
                    if let (Some(p), false, false) = (p, o, u) {
                        *shapes.entry(p.iter().map(|s| (s.field, s.value)).collect()).or_default() += 1;
                    }
                }
                let mut v: Vec<_> = shapes.into_iter().collect();
                v.sort_by(|a, b| b.1.cmp(&a.1));
                for (sh, n) in v.iter().take(8) {
                    println!("   [diag] missed (trained service) x{n}: {}", sh.iter().map(|(f, x)| format!("{f}:{x:x}")).collect::<Vec<_>>().join(" "));
                }
            }
        }
        p1 &= rate(&ok) >= 0.95;
        _p1x &= rate(&ok_x) >= 0.99;
        _p1b &= !probe41000.is_empty() && probe41000.iter().all(|&x| x);
        p5.push(rate(&ok) - pass_strict);
        p8 &= !allow.folded_fields().keys().any(|&f| f == F_TCPF || f == F_SRC || f == F_DST);
        let mut cls = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for p in held_paths.iter().flatten() {
            for (i, m) in mutations(p, &allow, untrained_port, end_host).into_iter().enumerate() {
                if let Some(m) = m {
                    cls[i].push(!pass(&allow, &empty, Some(&m)));
                }
            }
        }
        let names = ["exact port", "exact address", "protocol swap", "direction flip (end hosts)"];
        println!("   mutations dropped: {}", (0..4).map(|i| format!("{} {:.4} (n {})", names[i], rate(&cls[i]), cls[i].len())).collect::<Vec<_>>().join(", "));
        p3 &= cls.iter().filter(|c| !c.is_empty()).all(|c| rate(c) >= 0.99);
        p4 &= held_paths.iter().all(|p| !pass(&World::default(), &empty, p.as_ref()));
        p4 &= held.iter().filter(|r| r.frame.len() > 30).all(|r| !pass(&allow, &empty, sense(&r.frame[..30], r.outbound).as_ref()));
        let deny_train: Vec<Path> = raw_train.iter().filter_map(|(p, _)| mutations(p, &allow, untrained_port, end_host)[0].as_ref().map(expand)).collect();
        let deny = World::train(&deny_train, None);
        let harmed = held_paths.iter().flatten().map(expand).filter(|e| allow.matches(e) && deny.matches(e)).count();
        let held_a: Vec<Path> = held_paths.iter().flatten().filter_map(|p| mutations(p, &allow, untrained_port, end_host)[0].as_ref().map(expand)).collect();
        let deny_catches = held_a.iter().filter(|m| deny.matches(m)).count();
        println!("   deny world ({} paths): catches {deny_catches} of {} held-out class (a); legitimate packets it would wrongly drop: {harmed}", deny_train.len(), held_a.len());
        deny_harm += harmed;
        if role == "receiver" {
            receiver_world = Some(allow.clone());
        }
        bench.push((allow, held_paths.iter().flatten().map(expand).collect::<Vec<_>>()));
    }
    let probes = read_pcap(&format!("{ev}/lightcone-vm-20260930-phase1/receiver/control/mesh.pcap"));
    let rw = receiver_world.unwrap();
    println!("(P2 withdrawn) phase-1 probe to UDP 45999, a trained service here: passes {:?}", probes.iter().map(|r| pass(&rw, &empty, sense(&r.frame, r.outbound).as_ref())).collect::<Vec<_>>());
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
        ("P1 held-out pass >= 0.95 every role", p1),
        ("P3 exact-field mutations stopped (each class >= 0.99)", p3),
        ("P4 fail-closed", p4),
        ("P5 folding load-bearing (>= 0.2 gain)", p5.iter().all(|&g| g >= 0.2)),
        ("P6 the deny world harms no legitimate packet", deny_harm == 0),
        ("P7 >= 5,000,000 admissions per second", per_s >= 5e6),
        ("P8 no TCP-flag wildcard and no address wildcard", p8),
    ];
    println!();
    for (name, ok) in &v {
        println!("{} {name}", if *ok { "HOLDS " } else { "FAILS " });
    }
    println!("\n{} of {} hold", v.iter().filter(|x| x.1).count(), v.len());
}
