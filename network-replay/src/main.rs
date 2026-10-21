//! Offline packet replay with detailed, passive Lightcone receipts.

use kernel_lightcone::{bit, embedded, hash, Direction, Policy, World, EDGE_WORDS};
use network_lightcone_observer::{decode, ObservationKind};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
mod trace;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut file = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    Ok(hex(&digest.finalize()))
}

struct Args {
    input: PathBuf,
    output: PathBuf,
    include_addresses: bool,
    max_frames: u64,
    trace: bool,
    include_frame_bytes: bool,
}

fn args() -> Result<Args> {
    let mut input = None;
    let mut output = None;
    let mut include_addresses = false;
    let mut max_frames = 1_000u64;
    let mut trace = true;
    let mut include_frame_bytes = false;
    let mut tokens = env::args().skip(1);
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--input" => {
                input = Some(PathBuf::from(
                    tokens
                        .next()
                        .ok_or_else(|| invalid("--input needs a path"))?,
                ))
            }
            "--out" => {
                output = Some(PathBuf::from(
                    tokens.next().ok_or_else(|| invalid("--out needs a path"))?,
                ))
            }
            "--include-addresses" => include_addresses = true,
            "--trace" => trace = true,
            "--no-trace" => trace = false,
            "--include-frame-bytes" => include_frame_bytes = true,
            "--max-frames" => {
                let raw = tokens
                    .next()
                    .ok_or_else(|| invalid("--max-frames needs a number"))?;
                max_frames = raw
                    .parse()
                    .map_err(|_| invalid("--max-frames must be an integer"))?;
                if max_frames == 0 || max_frames > 1_000_000 {
                    return Err(invalid("--max-frames must be between 1 and 1,000,000"));
                }
            }
            "--help" | "-h" => {
                println!("Usage: network-lightcone-replay --input CAPTURE.hex|CAPTURE.pcap --out NEW_LOG_DIRECTORY [--no-trace] [--include-frame-bytes] [--include-addresses] [--max-frames N]");
                std::process::exit(0);
            }
            _ => return Err(invalid(format!("unknown argument: {token}"))),
        }
    }
    let input = input.ok_or_else(|| invalid("--input is required"))?;
    let output = output.ok_or_else(|| invalid("--out is required"))?;
    if !input.is_file() {
        return Err(invalid(format!("input is not a file: {}", input.display())));
    }
    if output.exists() {
        return Err(invalid(format!(
            "refusing to overwrite log directory: {}",
            output.display()
        )));
    }
    Ok(Args {
        input,
        output,
        include_addresses,
        max_frames,
        trace,
        include_frame_bytes,
    })
}

struct Context {
    world: World<'static>,
    policy: Policy,
    world_sha256: String,
    pack_sha256: String,
    pack_manifest_sha256: String,
    training_receipt_sha256: String,
    pack_status: String,
    sealed: bool,
    implementation_sources_sha256: BTreeMap<String, String>,
    executable_sha256: String,
    run_id: String,
    world_snapshot_sha256: String,
    source_tree_matches_build: bool,
}

fn load_context(lifecycle: &mut trace::Lifecycle) -> Result<Context> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| invalid("replay crate has no project root"))?;
    let lightcone = root.join("network-lightcone");
    let coverage: Value = serde_json::from_slice(&fs::read(lightcone.join("coverage.json"))?)?;
    let relative = coverage["local_validation"]["pack"]
        .as_str()
        .ok_or_else(|| invalid("coverage has no active local pack"))?;
    let relative_path = Path::new(relative);
    if !relative.starts_with("worlds/")
        || relative_path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::RootDir))
    {
        return Err(invalid("active pack path escapes the world directory"));
    }
    let pack_dir = lightcone.join(relative_path);
    let packed_world = fs::read(pack_dir.join("world.json"))?;
    let current_world = fs::read(lightcone.join("sources/world.json"))?;
    if packed_world != current_world {
        return Err(invalid("active pack was built from another world revision"));
    }
    let world_sha = hash(&packed_world);
    let world_sha256 = hex(&world_sha);
    let world_record: Value = serde_json::from_slice(&packed_world)?;
    let manifest_path = pack_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let pack_manifest_sha256 = hex(&hash(&manifest_bytes));
    if coverage["local_validation"]["manifest_sha256"].as_str()
        != Some(pack_manifest_sha256.as_str())
    {
        return Err(invalid("coverage ledger and active pack manifest differ"));
    }
    let files = manifest["files"]
        .as_object()
        .ok_or_else(|| invalid("pack manifest has no file hash map"))?;
    for (name, expected) in files {
        let path = Path::new(name);
        if path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(invalid("pack manifest contains a non-local file path"));
        }
        let actual = file_sha256(&pack_dir.join(path))?;
        lifecycle.record(
            "pack_file_checked",
            json!({"name":name,"expected_sha256":expected,"actual_sha256":actual}),
        )?;
        if actual != expected.as_str().unwrap_or("") {
            return Err(invalid(format!("pack file hash differs: {name}")));
        }
    }
    let training_receipt_sha256 = files["training.json"]
        .as_str()
        .ok_or_else(|| invalid("pack manifest has no training receipt hash"))?
        .to_string();
    if coverage["local_validation"]["training_sha256"].as_str()
        != Some(training_receipt_sha256.as_str())
    {
        return Err(invalid("coverage ledger and training receipt differ"));
    }
    let pack_sha256 = hex(&embedded::HASH);
    if manifest["files"]["world.bin"].as_str() != Some(pack_sha256.as_str())
        || manifest["source_sha256"].as_str() != Some(world_sha256.as_str())
        || fs::read(pack_dir.join("world.bin"))? != embedded::PACK
    {
        return Err(invalid("embedded pack, manifest, and source hashes differ"));
    }
    let world = World::load(embedded::PACK, embedded::HASH)
        .map_err(|error| invalid(format!("embedded pack failed runtime load: {error:?}")))?;
    lifecycle.record("runtime_pack_loaded",json!({"nodes":world.node_count(),"edges":world.edge_count(),
        "full_dimensions":48,"observer_dimensions":4,"pack_sha256":pack_sha256,
        "checks":"hash, format, metadata bounds, coordinates, observer projection, typed edge references"}))?;
    if world.source_digest() != &world_sha[..] {
        return Err(invalid("runtime source digest differs from world source"));
    }
    let policy_record = &world_record["policy"];
    let direction = match policy_record["direction"].as_str() {
        Some("past") => Direction::Past,
        Some("future") => Direction::Future,
        Some("both") => Direction::Both,
        _ => return Err(invalid("unsupported world policy direction")),
    };
    let polarity = match policy_record["polarity"].as_str() {
        Some("negative") => -1,
        Some("positive") => 1,
        Some("both") => 0,
        _ => return Err(invalid("unsupported world policy polarity")),
    };
    let hops = u8::try_from(
        policy_record["max_hops"]
            .as_u64()
            .ok_or_else(|| invalid("missing max_hops"))?,
    )?;
    let max_nodes = u16::try_from(
        policy_record["max_nodes"]
            .as_u64()
            .ok_or_else(|| invalid("missing max_nodes"))?,
    )?;
    let relations = u8::try_from(
        policy_record["relation_mask"]
            .as_u64()
            .ok_or_else(|| invalid("missing relation_mask"))?,
    )?;
    let pack_status = manifest["status"]
        .as_str()
        .ok_or_else(|| invalid("pack has no status"))?
        .to_string();
    let sealed = manifest["sealed"]
        .as_bool()
        .ok_or_else(|| invalid("pack has no sealed flag"))?;
    let mut implementation_sources_sha256 = BTreeMap::new();
    let mut source_tree_matches_build = true;
    for (name, path, compiled) in [
        (
            "runtime",
            root.join("kernel-lightcone/src/lib.rs"),
            include_bytes!("../../kernel-lightcone/src/lib.rs").as_slice(),
        ),
        (
            "observer",
            root.join("network-observer/src/lib.rs"),
            include_bytes!("../../network-observer/src/lib.rs").as_slice(),
        ),
        (
            "replay",
            root.join("network-replay/src/main.rs"),
            include_bytes!("main.rs").as_slice(),
        ),
        (
            "trace",
            root.join("network-replay/src/trace.rs"),
            include_bytes!("trace.rs").as_slice(),
        ),
        (
            "cargo_lock",
            root.join("Cargo.lock"),
            include_bytes!("../../Cargo.lock").as_slice(),
        ),
    ] {
        let compiled_hash = hex(&hash(compiled));
        source_tree_matches_build &= file_sha256(&path)? == compiled_hash;
        implementation_sources_sha256.insert(name.to_string(), compiled_hash);
    }
    let executable_sha256 = file_sha256(&env::current_exe()?)?;
    Ok(Context {
        world,
        policy: Policy {
            direction,
            hops,
            max_nodes,
            relations,
            polarity,
        },
        world_sha256,
        pack_sha256,
        pack_manifest_sha256,
        training_receipt_sha256,
        pack_status,
        sealed,
        implementation_sources_sha256,
        executable_sha256,
        run_id: String::new(),
        world_snapshot_sha256: String::new(),
        source_tree_matches_build,
    })
}

fn node_records<const N: usize>(world: &World<'_>, mask: &[u64; N]) -> Result<Vec<Value>> {
    let mut records = Vec::new();
    for index in 0..world.node_count() {
        if bit(mask, index) {
            let raw = world
                .node_json(index)
                .map_err(|error| invalid(format!("node {index}: {error:?}")))?;
            records.push(json!({"index": index, "record": serde_json::from_str::<Value>(raw)?}));
        }
    }
    Ok(records)
}

fn edge_records(world: &World<'_>, mask: &[u64; EDGE_WORDS]) -> Result<Vec<Value>> {
    let mut records = Vec::new();
    for index in 0..world.edge_count() {
        if bit(mask, index) {
            let raw = world
                .edge_json(index)
                .map_err(|error| invalid(format!("edge {index}: {error:?}")))?;
            records.push(json!({"index": index, "record": serde_json::from_str::<Value>(raw)?}));
        }
    }
    Ok(records)
}

fn wire_hint(frame: &[u8], include_addresses: bool) -> Value {
    if frame.len() < 14 {
        return json!({"ethernet_header_present": false});
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut hint = json!({"ethernet_header_present": true, "ethertype": format!("0x{ether_type:04x}"), "untrusted_until_decoded": true});
    let packet = &frame[14..];
    if ether_type == 0x0800 && packet.len() >= 20 {
        hint["ip_version"] = json!(packet[0] >> 4);
        hint["next_protocol_number"] = json!(packet[9]);
        hint["declared_ip_length"] = json!(u16::from_be_bytes([packet[2], packet[3]]));
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        if matches!(packet[9], 6 | 17) && header_len >= 20 && packet.len() >= header_len + 4 {
            hint["source_port"] = json!(u16::from_be_bytes([
                packet[header_len],
                packet[header_len + 1]
            ]));
            hint["destination_port"] = json!(u16::from_be_bytes([
                packet[header_len + 2],
                packet[header_len + 3]
            ]));
        }
        if include_addresses {
            hint["source_address"] =
                json!(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string());
            hint["destination_address"] =
                json!(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string());
        }
    } else if ether_type == 0x86dd && packet.len() >= 40 {
        hint["ip_version"] = json!(packet[0] >> 4);
        hint["next_protocol_number"] = json!(packet[6]);
        hint["declared_ip_length"] = json!(u16::from_be_bytes([packet[4], packet[5]]));
        if matches!(packet[6], 6 | 17) && packet.len() >= 44 {
            hint["source_port"] = json!(u16::from_be_bytes([packet[40], packet[41]]));
            hint["destination_port"] = json!(u16::from_be_bytes([packet[42], packet[43]]));
        }
        if include_addresses {
            let mut source = [0u8; 16];
            source.copy_from_slice(&packet[8..24]);
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&packet[24..40]);
            hint["source_address"] = json!(Ipv6Addr::from(source).to_string());
            hint["destination_address"] = json!(Ipv6Addr::from(destination).to_string());
        }
    }
    hint
}

fn kind_label(kind: ObservationKind) -> &'static str {
    match kind {
        ObservationKind::Decoded => "decoded",
        ObservationKind::Unknown => "unknown",
        ObservationKind::Malformed => "malformed",
        ObservationKind::Fragment => "fragment",
    }
}

fn policy_json(policy: Policy) -> Value {
    let direction = match policy.direction {
        Direction::Past => "past",
        Direction::Future => "future",
        Direction::Both => "both",
    };
    json!({"direction": direction, "max_hops": policy.hops, "max_nodes": policy.max_nodes, "relation_mask": policy.relations, "polarity": policy.polarity})
}

struct FrameOutcome {
    event: Value,
    kind: String,
    reason: String,
    admission: String,
    total_us: u64,
    admitted_nodes: u64,
    admitted_edges: u64,
}

fn inspect_frame(
    context: &Context,
    index: u64,
    frame: &[u8],
    capture: Value,
    truncated: bool,
    args: &Args,
) -> Result<FrameOutcome> {
    let started = Instant::now();
    let mut timeline = trace::FrameTrace::new(args.trace);
    timeline.record(
        "pipeline",
        json!({"action":"input_received","bytes":frame.len(),"capture_truncated":truncated}),
    );
    let observation = if args.trace {
        network_lightcone_observer::decode_traced(frame, &mut |event| timeline.observer(event))
    } else {
        decode(frame)
    };
    let decode_us = started.elapsed().as_micros() as u64;
    let query_hash = hash(frame);
    let seed_started = Instant::now();
    let seed_records = node_records(&context.world, &observation.seeds)?;
    timeline.record("pipeline",json!({"action":"seed_metadata_resolved","seeds":seed_records.iter().map(|n|n["index"].clone()).collect::<Vec<_>>()}));
    let seed_metadata_us = seed_started.elapsed().as_micros() as u64;
    let admit_started = Instant::now();
    let receipt_result = if truncated {
        timeline.record(
            "pipeline",
            json!({"action":"admission_skipped","reason":"capture_truncated"}),
        );
        None
    } else if args.trace {
        Some(context.world.admit_traced(
            observation.seeds,
            context.policy,
            query_hash,
            &mut |event| timeline.admission(event),
        ))
    } else {
        Some(
            context
                .world
                .admit(observation.seeds, context.policy, query_hash),
        )
    };
    let runtime_admission_us = admit_started.elapsed().as_micros() as u64;
    let explanation_started = Instant::now();
    let (admission, admission_label, admitted_nodes, admitted_edges) = if truncated {
        (
            json!({"status": "capture_truncated", "attempted": false, "reason": "captured bytes do not cover the original frame"}),
            "capture_truncated".to_string(),
            0,
            0,
        )
    } else {
        match receipt_result.expect("non-truncated frame has an admission result") {
            Ok(receipt) => {
                let nodes = node_records(&context.world, &receipt.nodes)?;
                let edges = edge_records(&context.world, &receipt.edges)?;
                let excluded = node_records(&context.world, &receipt.excluded)?;
                let hop_frontier = node_records(&context.world, &receipt.hop_frontier)?;
                let label = if nodes.is_empty() {
                    "empty_neighborhood"
                } else {
                    "context_admitted"
                };
                let node_count = nodes.len() as u64;
                let edge_count = edges.len() as u64;
                (
                    json!({
                        "status": label,
                        "attempted": true,
                        "policy": policy_json(context.policy),
                        "world_pack_sha256": context.pack_sha256,
                        "query_sha256": hex(&receipt.query),
                        "receipt_sha256": hex(&receipt.digest),
                        "nodes": nodes,
                        "edges": edges,
                        "excluded": excluded,
                        "hop_frontier": hop_frontier,
                        "authorization_verdict": null,
                    }),
                    label.to_string(),
                    node_count,
                    edge_count,
                )
            }
            Err(error) => (
                json!({"status": "runtime_error", "attempted": true, "error": format!("{error:?}"), "authorization_verdict": null}),
                "runtime_error".to_string(),
                0,
                0,
            ),
        }
    };
    let explanation_us = explanation_started.elapsed().as_micros() as u64;
    timeline.record("pipeline",json!({"action":"output_ready","status":admission_label,"receipt_sha256":admission["receipt_sha256"]}));
    let total_us = started.elapsed().as_micros() as u64;
    let event = json!({
        "schema": 2,
        "run_id": context.run_id,
        "event_id": format!("{}:{index}",context.run_id),
        "sequence": index,
        "capture": capture,
        "frame_len": frame.len(),
        "frame_sha256": hex(&query_hash),
        "wire_hint": wire_hint(frame, args.include_addresses || args.include_frame_bytes),
        "frame_hex": if args.include_frame_bytes {Some(hex(frame))} else {None},
        "trace_enabled": args.trace,
        "trace": timeline.events,
        "observer": {
            "kind": kind_label(observation.kind),
            "reason": observation.reason,
            "seeds": seed_records,
        },
        "admission": admission,
        "timing_us": {"decode": decode_us, "seed_metadata": seed_metadata_us, "runtime_admission": runtime_admission_us, "result_explanation": explanation_us, "total_processing": total_us},
        "scope": "passive causal context; no packet release or host authorization decision",
    });
    Ok(FrameOutcome {
        event,
        kind: kind_label(observation.kind).to_string(),
        reason: observation.reason.to_string(),
        admission: admission_label,
        total_us,
        admitted_nodes,
        admitted_edges,
    })
}

#[derive(Default)]
struct Stats {
    frames: u64,
    kinds: BTreeMap<String, u64>,
    reasons: BTreeMap<String, u64>,
    admissions: BTreeMap<String, u64>,
    durations_us: Vec<u64>,
    total_admitted_nodes: u64,
    total_admitted_edges: u64,
}

struct EventLog {
    writer: BufWriter<File>,
    digest: Sha256,
    stats: Stats,
    last_event_sha256: Option<String>,
}

impl EventLog {
    fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::new(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?,
            ),
            digest: Sha256::new(),
            stats: Stats::default(),
            last_event_sha256: None,
        })
    }

    fn record(&mut self, mut outcome: FrameOutcome) -> Result<()> {
        outcome.event["previous_event_sha256"] = json!(self.last_event_sha256);
        let event_hash = hex(&hash(&serde_json::to_vec(&outcome.event)?));
        outcome.event["event_sha256"] = json!(event_hash);
        let mut bytes = serde_json::to_vec(&outcome.event)?;
        bytes.push(b'\n');
        self.writer.write_all(&bytes)?;
        self.writer.flush()?;
        self.last_event_sha256 = Some(event_hash);
        self.digest.update(&bytes);
        self.stats.frames += 1;
        *self.stats.kinds.entry(outcome.kind).or_default() += 1;
        *self.stats.reasons.entry(outcome.reason).or_default() += 1;
        *self.stats.admissions.entry(outcome.admission).or_default() += 1;
        self.stats.durations_us.push(outcome.total_us);
        self.stats.total_admitted_nodes += outcome.admitted_nodes;
        self.stats.total_admitted_edges += outcome.admitted_edges;
        Ok(())
    }

    fn finish(
        &mut self,
        path: &Path,
        args: &Args,
        context: &Context,
        input_hash: &str,
        final_input_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        self.writer.flush()?;
        let mut ordered = self.stats.durations_us.clone();
        ordered.sort_unstable();
        let p95_us = if ordered.is_empty() {
            0
        } else {
            ordered[((ordered.len() * 95).div_ceil(100)).saturating_sub(1)]
        };
        let input_name = args
            .input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("capture");
        let started_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let summary = json!({
            "schema": 2,
            "run_id": context.run_id,
            "status": if error.is_some() { "failed" } else { "completed" },
            "error": error,
            "generated_unix_seconds": started_unix,
            "logger_version": env!("CARGO_PKG_VERSION"),
            "input_name": input_name,
            "input_sha256": input_hash,
            "input_sha256_after_replay": final_input_hash,
            "input_hash_stable": final_input_hash == Some(input_hash),
            "events_sha256": hex(&self.digest.clone().finalize()),
            "last_event_sha256": self.last_event_sha256,
            "world_snapshot_sha256": context.world_snapshot_sha256,
            "lifecycle_sha256": file_sha256(&args.output.join("lifecycle.jsonl"))?,
            "executable_sha256": context.executable_sha256,
            "implementation_sources_sha256": context.implementation_sources_sha256,
            "source_tree_matches_build": context.source_tree_matches_build,
            "world_source_sha256": context.world_sha256,
            "world_pack_sha256": context.pack_sha256,
            "pack_manifest_sha256": context.pack_manifest_sha256,
            "training_receipt_sha256": context.training_receipt_sha256,
            "pack_status": context.pack_status,
            "sealed": context.sealed,
            "passive": true,
            "addresses_included": args.include_addresses || args.include_frame_bytes,
            "max_frames": args.max_frames,
            "payload_bytes_logged": args.include_frame_bytes,
            "trace_enabled": args.trace,
            "timing_scope": "processing includes trace callbacks; excludes event JSON serialization and disk writes",
            "policy": policy_json(context.policy),
            "frames": self.stats.frames,
            "observer_kinds": self.stats.kinds,
            "observer_reasons": self.stats.reasons,
            "admission_statuses": self.stats.admissions,
            "total_admitted_nodes": self.stats.total_admitted_nodes,
            "total_admitted_edges": self.stats.total_admitted_edges,
            "p95_total_us": p95_us,
            "scope": "offline observation and causal admission only; no host authorization or attack-reduction claim",
        });
        fs::write(path, serde_json::to_vec_pretty(&summary)?)?;
        Ok(())
    }
}

fn parse_hex(line: &str) -> Result<Vec<u8>> {
    let cleaned: String = line
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if cleaned.is_empty()
        || cleaned.len() % 2 != 0
        || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(
            "invalid hex frame: expected pairs of hexadecimal digits",
        ));
    }
    if cleaned.len() / 2 > 1_048_576 {
        return Err(invalid("hex frame exceeds 1 MiB limit"));
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let value = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        bytes.push(value);
    }
    Ok(bytes)
}

fn replay_hex(args: &Args, context: &Context, log: &mut EventLog) -> Result<()> {
    let reader = BufReader::new(File::open(&args.input)?);
    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        if log.stats.frames >= args.max_frames {
            return Err(invalid(format!(
                "frame limit {} reached; log is incomplete",
                args.max_frames
            )));
        }
        let frame = parse_hex(content)
            .map_err(|error| invalid(format!("line {}: {error}", line_number + 1)))?;
        let outcome = inspect_frame(
            context,
            log.stats.frames + 1,
            &frame,
            json!({"line": line_number + 1, "format": "hex"}),
            false,
            args,
        )?;
        log.record(outcome)?;
    }
    Ok(())
}

fn read_number(bytes: &[u8], little: bool) -> u32 {
    let array: [u8; 4] = bytes.try_into().expect("fixed-width capture header");
    if little {
        u32::from_le_bytes(array)
    } else {
        u32::from_be_bytes(array)
    }
}

fn replay_pcap(args: &Args, context: &Context, log: &mut EventLog) -> Result<()> {
    let mut reader = BufReader::new(File::open(&args.input)?);
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let (little, resolution) = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, "microseconds"),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, "microseconds"),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, "nanoseconds"),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, "nanoseconds"),
        _ => {
            return Err(invalid(
                "unsupported capture format; expected classic PCAP Ethernet",
            ))
        }
    };
    let snaplen = read_number(&header[16..20], little);
    let linktype = read_number(&header[20..24], little);
    if linktype != 1 {
        return Err(invalid(format!(
            "unsupported PCAP linktype {linktype}; Ethernet (1) is required"
        )));
    }
    if snaplen == 0 || snaplen > 1_048_576 {
        return Err(invalid("invalid PCAP snapshot length"));
    }
    loop {
        let mut record = [0u8; 16];
        match reader.read_exact(&mut record[..1]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        }
        if log.stats.frames >= args.max_frames {
            return Err(invalid(format!(
                "frame limit {} reached; log is incomplete",
                args.max_frames
            )));
        }
        reader.read_exact(&mut record[1..])?;
        let seconds = read_number(&record[0..4], little);
        let fraction = read_number(&record[4..8], little);
        let captured_len = read_number(&record[8..12], little);
        let original_len = read_number(&record[12..16], little);
        if captured_len > snaplen || captured_len > original_len || captured_len > 1_048_576 {
            return Err(invalid(format!(
                "invalid PCAP record length at frame {}",
                log.stats.frames + 1
            )));
        }
        let mut frame = vec![0u8; captured_len as usize];
        reader.read_exact(&mut frame)?;
        let outcome = inspect_frame(
            context,
            log.stats.frames + 1,
            &frame,
            json!({"format": "pcap", "timestamp_seconds": seconds, "timestamp_fraction": fraction, "timestamp_unit": resolution, "captured_len": captured_len, "original_len": original_len}),
            captured_len < original_len,
            args,
        )?;
        log.record(outcome)?;
    }
    Ok(())
}

fn run() -> Result<()> {
    let args = args()?;
    if let Some(parent) = args.output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&args.output)?;
    let lifecycle_path = args.output.join("lifecycle.jsonl");
    let mut lifecycle = trace::Lifecycle::new(&lifecycle_path)?;
    lifecycle.record("run_started",json!({"input":args.input,"trace_enabled":args.trace,"frame_bytes_included":args.include_frame_bytes}))?;
    let result = run_logged(&args, &mut lifecycle);
    lifecycle.record(
        if result.is_ok() {
            "run_completed"
        } else {
            "run_failed"
        },
        json!({"error":result.as_ref().err().map(|e|e.to_string())}),
    )?;
    let summary_path = args.output.join("summary.json");
    let mut summary = if summary_path.exists() {
        serde_json::from_slice::<Value>(&fs::read(&summary_path)?)?
    } else {
        json!({"schema":2,"frames":0,"passive":true,"scope":"failed before replay completion"})
    };
    summary["status"] = json!(if result.is_ok() {
        "completed"
    } else {
        "failed"
    });
    summary["error"] = json!(result.as_ref().err().map(|e| e.to_string()));
    summary["lifecycle_sha256"] = json!(file_sha256(&lifecycle_path)?);
    fs::write(summary_path, serde_json::to_vec_pretty(&summary)?)?;
    result
}

fn run_logged(args: &Args, lifecycle: &mut trace::Lifecycle) -> Result<()> {
    lifecycle.record("world_validation_started", json!({}))?;
    let mut context = load_context(lifecycle)?;
    lifecycle.record("input_hash_started", json!({}))?;
    let input_hash = file_sha256(&args.input)?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    context.run_id = hex(&hash(
        format!("{input_hash}:{nonce}:{}", std::process::id()).as_bytes(),
    ));
    lifecycle.record(
        "input_identified",
        json!({"run_id":context.run_id,"input_sha256":input_hash}),
    )?;
    let snapshot = serde_json::to_vec_pretty(&trace::world_snapshot(&context)?)?;
    context.world_snapshot_sha256 = hex(&hash(&snapshot));
    fs::write(args.output.join("world.json"), snapshot)?;
    let format = args
        .input
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if format != "hex" && format != "pcap" {
        return Err(invalid("input extension must be .hex or .pcap"));
    }
    let events_path = args.output.join("events.jsonl");
    let summary_path = args.output.join("summary.json");
    let mut log = EventLog::new(&events_path)?;
    lifecycle.record(
        "replay_started",
        json!({"format":format,"policy":policy_json(context.policy)}),
    )?;
    let result = if format == "hex" {
        replay_hex(args, &context, &mut log)
    } else {
        replay_pcap(args, &context, &mut log)
    };
    let mut errors = Vec::new();
    if let Err(error) = result {
        errors.push(error.to_string());
    }
    let final_input_hash = match file_sha256(&args.input) {
        Ok(value) => {
            if value != input_hash {
                errors.push("input file changed during replay".to_string());
            }
            Some(value)
        }
        Err(error) => {
            errors.push(format!("could not rehash input after replay: {error}"));
            None
        }
    };
    let error = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };
    lifecycle.record("replay_finished",json!({"frames":log.stats.frames,"error":error,"input_sha256_after_replay":final_input_hash}))?;
    log.finish(
        &summary_path,
        args,
        &context,
        &input_hash,
        final_input_hash.as_deref(),
        error.as_deref(),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"status": if error.is_some() { "failed" } else { "completed" }, "frames": log.stats.frames, "events": events_path, "summary": summary_path})
        )?
    );
    if let Some(error) = error {
        return Err(invalid(error));
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("network-lightcone-replay: {error}");
        std::process::exit(1);
    }
}
