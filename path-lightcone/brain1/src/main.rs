//! CONSOLIDATE-1 orchestrator (path-lightcone/CONSOLIDATE-1-PRECOMMIT.md), door two.
//!
//! Usage: brain1 RUN_DIR OLD_PACK_DIR OUT_DIR
//!   RUN_DIR/<role>/ep<k>-gate.log   the gate's byte-logged verdicts in episode k
//!   RUN_DIR/<role>/ep<k>-self.txt   "addr <hex>" and "tun <ifindex>" lines: the host's own readings
//! The adversarial set (A1-A4) is derived offline from each role's trained paths and self
//! readings; see CONSOLIDATE-1-PRECOMMIT.md "Method change". Writes OUT_DIR/<role>.pathpack
//! (candidate packs) and prints the report. Every setting is here.

use path_admit::admit;
use path_frame::held_path;
use path_sense::{Path, Sym, F_DIR, F_DPORT, F_DST, F_L4, F_SPORT, F_SRC};
use path_self::{cause, Cause, SelfReadings};
use path_world::{CtxFold, World};
use std::collections::{BTreeMap, HashSet};

const FOLD: CtxFold = CtxFold { min_distinct: 3, ephemeral_fraction: 0.8 };
const LEARNING_EPISODES: [u32; 3] = [1, 2, 3];
const EVALUATION_EPISODE: u32 = 4;
const ROLES: [&str; 3] = ["hub", "source", "receiver"];
/// A physical-link interface index for the derived adversary: large, never a lab TUN index.
const PHYS_IF: u32 = 60000;
/// A link-local address the host never owns (for fabricated novelty).
const NOT_OWNED: u128 = 0xfe80_0000_0000_0000_dead_beef_dead_beef;

struct Worlds {
    allow: World,
    deny: World,
}

/// The same law and deny construction as pathgate and Imperium's imperium-net-pathworld.
fn worlds(train: &[Path]) -> Worlds {
    let seen: HashSet<Sym> = train.iter().flatten().copied().collect();
    let port = (40000u128..).find(|v| !seen.contains(&Sym { field: F_DPORT, value: *v }) && !seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap();
    let allow = World::train_context(train, FOLD);
    let deny_train: Vec<Path> = train
        .iter()
        .filter_map(|p| {
            let t = allow.match_trace(p)?;
            let at = |f: u8| p.iter().position(|s| s.field == f).filter(|&i| t[i]);
            let i = at(F_DPORT).or_else(|| at(F_SPORT))?;
            let mut q = p.clone();
            q[i].value = port;
            Some(q)
        })
        .collect();
    Worlds { deny: World::train(&deny_train), allow }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

struct Verdict {
    pass: bool,
    hook: u8,
    bytes: Vec<u8>,
    in_if: u32,
}

fn verdicts(file: &str) -> Vec<Verdict> {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with("V "))
        .filter_map(|l| {
            let v: Vec<&str> = l.split(' ').collect();
            Some(Verdict { pass: v.get(2)? == &"1", hook: v.get(4)?.parse().ok()?, bytes: unhex(v.get(5)?), in_if: v.get(6)?.parse().ok()? })
        })
        .collect()
}

fn readings(file: &str) -> SelfReadings {
    let mut r = SelfReadings::default();
    for l in std::fs::read_to_string(file).unwrap_or_default().lines() {
        match l.split_once(' ') {
            Some(("addr", h)) => {
                r.own_addresses.insert(u128::from_str_radix(h, 16).unwrap());
            }
            Some(("tun", i)) => {
                r.tunnels.insert(i.parse().unwrap());
            }
            _ => {}
        }
    }
    r
}


/// A1-A4, derived by field substitution from the role's trained paths plus a self address.
/// Each is a path the brain must read as Unexplained. Returns (path, hook, in_if).
fn adversary(old: &[Path], self_addr: u128, untrained_port: u128) -> Vec<(Path, u8, u32)> {
    let set = |p: &Path, f: u8, v: u128| -> Path {
        let mut q = p.clone();
        if let Some(i) = q.iter().position(|s| s.field == f) {
            q[i].value = v;
        }
        q
    };
    let has = |p: &Path, f: u8| p.iter().any(|s| s.field == f);
    let mut out = Vec::new();
    // A1: a trained inbound path, source spoofed to the host's OWN address, on a physical link.
    if let Some(p) = old.iter().find(|p| p.iter().any(|s| s.field == F_DIR && s.value == 0) && has(p, F_SRC)) {
        out.push((set(p, F_SRC, self_addr), 0u8, PHYS_IF));
    }
    // A2: a trained inbound path, source a link-local the host does NOT own, on a physical link.
    if let Some(p) = old.iter().find(|p| p.iter().any(|s| s.field == F_DIR && s.value == 0) && has(p, F_SRC)) {
        out.push((set(p, F_SRC, NOT_OWNED), 0, PHYS_IF));
    }
    // A3: outbound from the host's own address, but destination port untrained (novelty elsewhere).
    if let Some(p) = old.iter().find(|p| has(p, F_DPORT) && has(p, F_SRC)) {
        out.push((set(&set(p, F_SRC, self_addr), F_DPORT, untrained_port), 3, 0));
    }
    // A4: outbound exfiltration — own source, untrained destination and port.
    if let Some(p) = old.iter().find(|p| has(p, F_DPORT) && has(p, F_DST) && has(p, F_SRC)) {
        out.push((set(&set(&set(p, F_SRC, self_addr), F_DST, NOT_OWNED), F_DPORT, untrained_port), 3, 0));
    }
    // A5: protocol swap on a trained service (PATHGATE-3 negative, inbound).
    if let Some(p) = old.iter().find(|p| p.iter().any(|s| s.field == F_L4 && (s.value == 17 || s.value == 6)) && p.iter().any(|s| s.field == F_DIR && s.value == 0)) {
        let swapped = p.iter().find(|s| s.field == F_L4).map(|s| if s.value == 17 { 6 } else { 17 }).unwrap();
        out.push((set(p, F_L4, swapped), 0, PHYS_IF));
    }
    // A6: a trained inbound service from an untrained source address (not self).
    if let Some(p) = old.iter().find(|p| p.iter().any(|s| s.field == F_DIR && s.value == 0) && has(p, F_SRC) && has(p, F_DPORT)) {
        out.push((set(p, F_SRC, NOT_OWNED ^ 0x5a5a), 0, PHYS_IF));
    }
    out
}

fn untrained_port_of(train: &[Path]) -> u128 {
    let seen: HashSet<Sym> = train.iter().flatten().copied().collect();
    (40000u128..).find(|v| !seen.contains(&Sym { field: F_DPORT, value: *v }) && !seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (run, old_dir, out_dir) = (&a[1], &a[2], &a[3]);
    std::fs::create_dir_all(out_dir).unwrap();
    let (mut c1, mut c2, mut c3, mut c4, mut c6) = (true, true, true, true, true);
    for role in ROLES {
        let old = path_pack::decode(&std::fs::read_to_string(format!("{old_dir}/{role}.pathpack")).unwrap()).expect("old pack");
        let w = worlds(&old.paths);
        let mut evidence: Vec<Path> = Vec::new();
        let mut counts: BTreeMap<(u32, &str), usize> = BTreeMap::new();
        let mut episode_self_drops: BTreeMap<u32, usize> = BTreeMap::new();
        let mut self_addrs: HashSet<u128> = HashSet::new();
        for ep in LEARNING_EPISODES.iter().copied().chain([EVALUATION_EPISODE]) {
            let r = readings(&format!("{run}/{role}/ep{ep}-self.txt"));
            self_addrs.extend(r.own_addresses.iter().copied());
            for v in verdicts(&format!("{run}/{role}/ep{ep}-gate.log")).iter().filter(|v| !v.pass) {
                let Some(p) = held_path(&v.bytes, v.hook) else {
                    *counts.entry((ep, "no_path")).or_default() += 1;
                    continue;
                };
                let c = cause(&p, v.hook, v.in_if, &r, &w.allow);
                let label = match c {
                    Cause::OwnAddress => "own_address",
                    Cause::AuthenticatedTunnel => "authenticated_tunnel",
                    Cause::Unexplained => "unexplained",
                };
                *counts.entry((ep, label)).or_default() += 1;
                if c != Cause::Unexplained {
                    *episode_self_drops.entry(ep).or_default() += 1;
                    if LEARNING_EPISODES.contains(&ep) {
                        evidence.push(p);
                    }
                }
            }
        }
        // The derived adversary (A1-A4), read with a representative self address.
        let self_addr = self_addrs.iter().copied().min().unwrap_or(NOT_OWNED ^ 1);
        let adv = adversary(&old.paths, self_addr, untrained_port_of(&old.paths));
        let adv_readings = {
            let mut r = SelfReadings::default();
            r.own_addresses.insert(self_addr);
            r
        };
        let adv_all_unexplained = adv.iter().all(|(p, hook, in_if)| cause(p, *hook, *in_if, &adv_readings, &w.allow) == Cause::Unexplained);
        c1 &= adv_all_unexplained && !adv.is_empty();
        let adv_paths: Vec<Path> = adv.iter().map(|(p, _, _)| p.clone()).collect();

        let cand = path_consolidate::consolidate(&old.paths, &evidence, &w.deny);
        std::fs::write(format!("{out_dir}/{role}.pathpack"), path_pack::encode(role, &cand.paths)).unwrap();
        let cw = worlds(&cand.paths);
        let kept_old = old.paths.iter().all(|p| cand.paths.contains(p));
        let admits_evidence = evidence.iter().filter(|p| admit(&cw.allow, &cw.deny, Some(p))).count();
        let admits_adv = adv_paths.iter().filter(|p| admit(&cw.allow, &cw.deny, Some(p))).count();
        let adv_in_pack = adv_paths.iter().filter(|p| cand.paths.contains(p)).count();
        c2 &= adv_in_pack == 0 && evidence.iter().all(|p| cand.paths.contains(p) || w.deny.matches(p));
        c3 &= kept_old;
        c4 &= admits_evidence == evidence.len() && admits_adv == 0;
        let e1 = episode_self_drops.get(&1).copied().unwrap_or(0);
        let e4 = episode_self_drops.get(&EVALUATION_EPISODE).copied().unwrap_or(0);
        c6 &= e4 < e1;
        println!("[{role}] old {} paths -> candidate {} (+{} added, {} refused by deny)", old.paths.len(), cand.paths.len(), cand.added, cand.refused_by_deny);
        for ((ep, label), n) in &counts {
            println!("   episode {ep}: {label} {n}");
        }
        println!("   offline: candidate admits {admits_evidence}/{} self-caused drops, {admits_adv}/{} adversarial paths; adversarial in pack {adv_in_pack}; old paths kept {kept_old}", evidence.len(), adv_paths.len());
        println!("   self-caused drops: episode 1 {e1}, episode {EVALUATION_EPISODE} {e4}");
        println!("   wildcards per field: old {:?} -> candidate {:?}", w.allow.folded_fields(), cw.allow.folded_fields());
        for (pre, sib) in cw.allow.wild_contexts(3).into_iter().chain(cw.allow.wild_contexts(4)) {
            println!("   [diag] candidate address wildcard after {} ({sib} exact siblings)", pre.iter().map(|s| if s.value == path_world::WILD { format!("{}:*", s.field) } else { format!("{}:{:x}", s.field, s.value) }).collect::<Vec<_>>().join(" "));
        }
    }
    println!();
    for (n, ok) in [("C1 every adversarial path (A1-A4) unexplained", c1), ("C2 0 adversarial paths in packs; every self-caused drop in", c2), ("C3 add-only", c3), ("C4 candidate admits all self-caused, 0 adversarial (offline)", c4), ("C6 fewer self-caused drops in episode 4 than 1, every role", c6)] {
        println!("{} {n}", if ok { "HOLDS " } else { "FAILS " });
    }
}
