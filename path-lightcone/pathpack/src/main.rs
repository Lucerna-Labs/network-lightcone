//! Build a role's training pack (PATHCONE-1's split: the healthy arm's case attempts below 6, plus
//! background traffic) from Imperium's recorded packets. Usage: pathpack EVIDENCE ROLE OUT.

use path_sense::sense;

const TRAIN_ATTEMPTS: u32 = 6;

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let k = format!("\"{key}\": \"");
    let i = line.find(&k)? + k.len();
    let j = line[i..].find('"')? + i;
    Some(&line[i..j])
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (ev, role, out) = (&a[1], &a[2], &a[3]);
    let path = format!("{ev}/lightcone-vm-io-20261001/healthy-{role}-packets.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut paths = Vec::new();
    for l in text.lines() {
        let attempt = l.find("\"case_ids\": [").and_then(|i| {
            let rest = &l[i + 13..];
            let body = &rest[..rest.find(']')?];
            body.split(',').next()?.trim().trim_matches('"').rsplit_once(':')?.1.parse::<u32>().ok()
        });
        if attempt.map(|n| n >= TRAIN_ATTEMPTS).unwrap_or(false) {
            continue;
        }
        let (Some(dir), Some(hex)) = (field(l, "direction"), field(l, "captured_frame_hex")) else { continue };
        let frame: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0)).collect();
        if let Some(p) = sense(&frame, dir == "out") {
            paths.push(p);
        }
    }
    std::fs::write(out, path_pack::encode(role, &paths)).unwrap();
    println!("{role}: {} training paths -> {out}", paths.len());
}
