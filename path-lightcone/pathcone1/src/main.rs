//! PATHCONE-1 orchestrator (path-lightcone/PATHCONE-1-PRECOMMIT.md): trains one restrained allow
//! world per host role from Imperium's recorded VM traffic, builds the reverse deny world, and runs
//! checks P1–P7. Every setting lives here. Usage: pathcone1 IMPERIUM_EVIDENCE_DIR.

use path_admit::admit;
use path_sense::{sense, Path, Sym, F_DIR, F_DPORT, F_L4, F_SRC};
use path_world::{Fold, World, WILD};
use std::collections::HashMap;

const FOLD: Fold = Fold { min_distinct: 3, max_share: 0.5 };
const TRAIN_ATTEMPTS: u32 = 6;
const ROLES: [&str; 3] = ["hub", "source", "receiver"];

struct Rec {
    outbound: bool,
    frame: Vec<u8>,
    /// (case name, attempt index) for probe traffic; None for the host's own background.
    case: Option<(String, u32)>,
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
            Some(Rec { outbound, frame, case })
        })
        .collect()
}

/// SLL2 pcap frames with their direction (packet type 4 = outgoing).
fn read_pcap(path: &str) -> Vec<Rec> {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= b.len() {
        let cl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16;
        let f = b[off..off + cl].to_vec();
        off += cl;
        let outbound = f.get(10) == Some(&4);
        out.push(Rec { outbound, frame: f, case: None });
    }
    out
}

fn get(p: &Path, f: u8) -> Option<u128> {
    p.iter().find(|s| s.field == f).map(|s| s.value)
}

fn set(p: &Path, f: u8, v: u128) -> Path {
    p.iter().map(|s| if s.field == f { Sym { field: f, value: v } } else { *s }).collect()
}

/// The four mutation classes of a path (None where a class does not apply).
fn mutations(p: &Path, w: &World) -> [Option<Path>; 4] {
    let port = (40000u128..).find(|v| !w.seen.contains(&Sym { field: F_DPORT, value: *v })).unwrap();
    let a = get(p, F_DPORT).map(|_| set(p, F_DPORT, port));
    let b = get(p, F_SRC).map(|src| {
        let bad = if src > u32::MAX as u128 { 0x2001_0db8_0000_0000_0000_0000_0000_0badu128 } else { 0xcb00_71fa };
        set(p, F_SRC, bad)
    });
    let c = match get(p, F_L4) {
        Some(17) => Some(set(p, F_L4, 6)),
        Some(6) => Some(set(p, F_L4, 17)),
        _ => None,
    };
    let d = get(p, F_DIR).map(|x| set(p, F_DIR, 1 - x));
    [a, b, c, d]
}

fn rate(xs: &[bool]) -> f64 {
    xs.iter().filter(|&&x| x).count() as f64 / xs.len().max(1) as f64
}

fn main() {
    let ev = std::env::args().nth(1).expect("usage: pathcone1 IMPERIUM_EVIDENCE_DIR");
    let io = format!("{ev}/lightcone-vm-io-20261001");
    println!("PATHCONE-1: restrained trained-path allow world + reverse deny world; fold {FOLD:?}, train attempts < {TRAIN_ATTEMPTS}");
    let empty = World::default();
    let mut p1 = true;
    let mut p3 = true;
    let mut p5_gain = Vec::new();
    let mut deny_added = 0usize;
    let mut p6 = Vec::new();
    let mut bench_worlds = Vec::new();
    let mut receiver_world = None;
    let mut p4 = true;
    for role in ROLES {
        let healthy = read_jsonl(&format!("{io}/healthy-{role}-packets.jsonl"));
        let (train, mut held): (Vec<&Rec>, Vec<&Rec>) = healthy.iter().partition(|r| r.case.as_ref().map(|c| c.1 < TRAIN_ATTEMPTS).unwrap_or(true));
        let others: Vec<Rec> = ["quarantined", "kernel_recovered"].iter().flat_map(|arm| read_jsonl(&format!("{io}/{arm}-{role}-packets.jsonl"))).collect();
        held.extend(others.iter());
        let train_paths: Vec<Path> = train.iter().filter_map(|r| sense(&r.frame, r.outbound)).collect();
        let held_paths: Vec<Option<Path>> = held.iter().map(|r| sense(&r.frame, r.outbound)).collect();
        let allow = World::train(&train_paths, Some(FOLD));
        if std::env::var_os("PATHCONE_DIAG").is_some() {
            // Diagnostic (after run 1, not a prediction): folded fields, and which held-out mutation-(a)
            // packets passed (request vs reply: is the mutated port the side that was folded?).
            println!("   [diag] wildcards per field (0 dir,1 link,2 l4,3 src,4 dst,5 sport,6 dport,7 tcpf,8 icmp,9 arpop): {:?}", allow.folded_fields());
            let mut by: HashMap<(u128, bool), (usize, usize)> = HashMap::new();
            for p in held.iter().filter_map(|r| sense(&r.frame, r.outbound)).filter(|p| allow.matches(p)) {
                if let Some(m) = mutations(&p, &allow)[0].clone() {
                    let sport_low = get(&p, path_sense::F_SPORT).map(|v| v < 32768).unwrap_or(false);
                    let e = by.entry((get(&p, F_L4).unwrap_or(0), sport_low)).or_default();
                    e.0 += 1;
                    e.1 += allow.matches(&m) as usize;
                }
            }
            println!("   [diag] mutation (a) by (l4, source port < 32768 = reply-shaped): (n, passed) {by:?}");
        }
        let strict = World::train(&train_paths, None);
        // P1.
        let pass: Vec<bool> = held_paths.iter().map(|p| admit(&allow, &empty, p.as_ref())).collect();
        let pass_strict = rate(&held_paths.iter().map(|p| admit(&strict, &empty, p.as_ref())).collect::<Vec<_>>());
        let unparsed = held_paths.iter().filter(|p| p.is_none()).count();
        println!("[{role}] train {} paths ({} folds); held-out legitimate {}: pass {:.4} (no folding {:.4}); unparsable {}", train_paths.len(), allow.folds, held_paths.len(), rate(&pass), pass_strict, unparsed);
        let misses: HashMap<String, usize> = held.iter().zip(&pass).filter(|(_, &ok)| !ok).fold(HashMap::new(), |mut m, (r, _)| {
            *m.entry(r.case.as_ref().map(|c| c.0.clone()).unwrap_or_else(|| "background".into())).or_default() += 1;
            m
        });
        if !misses.is_empty() {
            println!("   held-out misses by case: {misses:?}");
        }
        p1 &= rate(&pass) >= 0.98;
        p5_gain.push(rate(&pass) - pass_strict);
        // P3.
        let mut cls = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for p in held_paths.iter().flatten().filter(|p| allow.matches(p)) {
            for (i, m) in mutations(p, &allow).into_iter().enumerate() {
                if let Some(m) = m {
                    cls[i].push(!admit(&allow, &empty, Some(&m)));
                }
            }
        }
        let names = ["dst port", "src address", "protocol swap", "direction flip"];
        println!("   mutations dropped: {}", (0..4).map(|i| format!("{} {:.4} (n {})", names[i], rate(&cls[i]), cls[i].len())).collect::<Vec<_>>().join(", "));
        p3 &= cls.iter().all(|c| rate(c) >= 0.99);
        // P4.
        p4 &= held_paths.iter().all(|p| !admit(&World::default(), &empty, p.as_ref()));
        p4 &= held.iter().filter(|r| r.frame.len() > 30).all(|r| !admit(&allow, &empty, sense(&r.frame[..30], r.outbound).as_ref()));
        // P6: the deny world, trained on class (a) of the training paths.
        let deny_train: Vec<Path> = train_paths.iter().filter_map(|p| mutations(p, &strict)[0].clone()).collect();
        let deny = World::train(&deny_train, None);
        let widened = World::train(&train_paths.iter().map(|p| set(p, F_DPORT, WILD)).collect::<Vec<_>>(), Some(FOLD));
        let held_a: Vec<Path> = held_paths.iter().flatten().filter_map(|p| mutations(p, &strict)[0].clone()).collect();
        let blocked_widened = rate(&held_a.iter().map(|m| !admit(&widened, &deny, Some(m))).collect::<Vec<_>>());
        let passed_widened_no_deny = rate(&held_a.iter().map(|m| admit(&widened, &empty, Some(m))).collect::<Vec<_>>());
        let legit_widened_deny = rate(&held_paths.iter().map(|p| admit(&widened, &deny, p.as_ref())).collect::<Vec<_>>());
        let added = held_paths.iter().flatten().filter(|p| allow.matches(p) && deny.matches(p)).count() + held_a.iter().filter(|m| allow.matches(m) && deny.matches(m)).count();
        deny_added += added;
        println!("   deny world: widened allow passes {passed_widened_no_deny:.4} of held-out class (a) alone, {:.4} with the deny world; legit pass under widened+deny {legit_widened_deny:.4}; drops the deny world adds to the plain allow world: {added}", 1.0 - blocked_widened);
        p6.push(blocked_widened);
        if role == "receiver" {
            receiver_world = Some(allow.clone());
        }
        bench_worlds.push((allow, held_paths.into_iter().flatten().collect::<Vec<_>>()));
    }
    // P2: the real negative, judged by the receiver's world.
    let probes = read_pcap(&format!("{ev}/lightcone-vm-20260930-phase1/receiver/control/mesh.pcap"));
    let rw = receiver_world.unwrap();
    let p2: Vec<bool> = probes.iter().map(|r| !admit(&rw, &empty, sense(&r.frame, r.outbound).as_ref())).collect();
    println!("P2 real negative (phase-1 undeclared UDP probe, {} packet(s)): dropped {:?}", probes.len(), p2);
    // P7.
    let (w, ps) = &bench_worlds[0];
    let t = std::time::Instant::now();
    let mut n = 0u64;
    let mut ok = 0u64;
    while n < 3_000_000 {
        for p in ps {
            ok += admit(w, &empty, Some(p)) as u64;
            n += 1;
        }
    }
    let per_s = n as f64 / t.elapsed().as_secs_f64();
    println!("P7 speed: {n} admissions in {:.3} s = {per_s:.0} per second (one thread; {ok} passed)", t.elapsed().as_secs_f64());
    let v = [
        ("P1 trained paths pass (held-out >= 0.98, every role)", p1),
        ("P2 the real negative is stopped", !p2.is_empty() && p2.iter().all(|&x| x)),
        ("P3 untrained paths stopped (each class >= 0.99)", p3),
        ("P4 fail-closed (empty world, truncated frames)", p4),
        ("P5 learned folding is load-bearing (>= 0.2 gain)", p5_gain.iter().all(|&g| g >= 0.2)),
        ("P6 deny world blocks class (a) under widened allow (>= 0.99)", p6.iter().all(|&b| b >= 0.99)),
        ("P6b deny adds 0 drops to the plain allow world", deny_added == 0),
        ("P7 >= 1,000,000 admissions per second", per_s >= 1e6),
    ];
    println!();
    for (name, okk) in &v {
        println!("{} {name}", if *okk { "HOLDS " } else { "FAILS " });
    }
    println!("\n{} of {} hold", v.iter().filter(|x| x.1).count(), v.len());
}
