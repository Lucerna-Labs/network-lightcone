//! Native catalog-query diagnostic: supplied host symbols are not wire-derived.
use kernel_lightcone::{bit, embedded, hash, Policy, World, MAX_NODES, NODE_WORDS};
use network_lightcone_observer::{add_host_validated_symbol, Observation, ObservationKind};
use serde_json::json;
use std::{
    env,
    fs::OpenOptions,
    io::{BufWriter, Write},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args().nth(1).ok_or("output JSONL path required")?;
    let world = World::load(embedded::PACK, embedded::HASH).map_err(|e| format!("load: {e:?}"))?;
    let source: serde_json::Value =
        serde_json::from_str(include_str!("../../network-lightcone/sources/world.json"))?;
    let p = &source["policy"];
    let policy = Policy {
        direction: kernel_lightcone::Direction::Both,
        hops: p["max_hops"].as_u64().ok_or("hops")? as u8,
        max_nodes: p["max_nodes"].as_u64().ok_or("max_nodes")? as u16,
        relations: p["relation_mask"].as_u64().ok_or("relations")? as u8,
        polarity: 0,
    };
    if p["direction"] != "both" || p["polarity"] != "both" {
        return Err("unexpected policy contract".into());
    }
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    for index in 0..world.node_count() + 3 {
        let mut observation = Observation {
            kind: ObservationKind::Decoded,
            seeds: [0; NODE_WORDS],
            reason: "explicit_host_test_symbol",
        };
        let (label, symbol) = if index < world.node_count() {
            ("represented", Some(index))
        } else if index == world.node_count() {
            ("empty", None)
        } else if index == world.node_count() + 1 {
            ("out_of_world", Some(world.node_count()))
        } else {
            ("out_of_capacity", Some(MAX_NODES))
        };
        let host_accepted = symbol.map(|s| add_host_validated_symbol(&mut observation, s));
        let query = hash(format!("C01:{index}:{label}").as_bytes());
        let mut trace = Vec::new();
        let mut emit = |e: kernel_lightcone::AdmissionStep| {
            trace.push(json!({"action":e.action,"node":e.node,"edge":e.edge,"neighbor":e.neighbor,"depth":e.depth}))
        };
        let result = world.admit_traced(observation.seeds, policy, query, &mut emit);
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let receipt = match result {
            Ok(r) => {
                json!({"nodes":(0..world.node_count()).filter(|i|bit(&r.nodes,*i)).collect::<Vec<_>>(),
                "edges":(0..world.edge_count()).filter(|i|bit(&r.edges,*i)).collect::<Vec<_>>(),
                "excluded":(0..world.node_count()).filter(|i|bit(&r.excluded,*i)).collect::<Vec<_>>(),
                "frontier":(0..world.node_count()).filter(|i|bit(&r.hop_frontier,*i)).collect::<Vec<_>>(),"digest":hex(&r.digest)})
            }
            Err(e) => json!({"error":format!("{e:?}")}),
        };
        serde_json::to_writer(
            &mut writer,
            &json!({"index":index,"kind":label,"symbol":symbol,"host_accepted":host_accepted,
            "query":hex(&query),"pack":hex(&world.digest),"receipt":receipt,"trace":trace}),
        )?;
        writer.write_all(b"\n")?;
    }
    let mut trace = Vec::new();
    let result = world.admit_traced(
        [0; NODE_WORDS],
        Policy {
            max_nodes: 0,
            ..policy
        },
        [0; 32],
        &mut |e| trace.push(e.action),
    );
    serde_json::to_writer(
        &mut writer,
        &json!({"kind":"invalid_policy","error":result.err().map(|e|format!("{e:?}")),"trace":trace}),
    )?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
