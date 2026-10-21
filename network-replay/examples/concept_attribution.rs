//! In-memory counterfactuals only. Never emits or promotes a modified world pack.
use kernel_lightcone::{bit, embedded, hash, set, Direction, Policy, World, NODE_WORDS};
use serde_json::{json, Value};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let input = args.next().ok_or("input JSON required")?;
    let output = args.next().ok_or("new output JSONL required")?;
    let input_bytes = fs::read(input)?;
    let inputs: Value = serde_json::from_slice(&input_bytes)?;
    let original =
        World::load(embedded::PACK, embedded::HASH).map_err(|e| format!("original: {e:?}"))?;
    let p = &inputs["policy"];
    let policy = Policy {
        direction: Direction::Both,
        hops: p["max_hops"].as_u64().ok_or("hops")? as u8,
        max_nodes: p["max_nodes"].as_u64().ok_or("max_nodes")? as u16,
        relations: p["relation_mask"].as_u64().ok_or("relations")? as u8,
        polarity: 0,
    };
    if p["direction"] != "both" || p["polarity"] != "both" {
        return Err("unexpected active policy".into());
    }
    let mut erased = embedded::PACK.to_vec();
    erased[84..1044].fill(0);
    for axis in 0..4 {
        let at = 84 + 48 * 4 + (axis * 4 + axis) * 4;
        erased[at..at + 4].copy_from_slice(&1_000_000i32.to_le_bytes());
    }
    let mut shuffled = embedded::PACK.to_vec();
    for i in 0..original.node_count() {
        let at = 1044 + i * 216 + 8;
        erased[at..at + 208].fill(0);
        let from = 1044 + (original.node_count() - 1 - i) * 216 + 8;
        shuffled[at..at + 208].copy_from_slice(&embedded::PACK[from..from + 208]);
    }
    let erased_world = World::load(&erased, hash(&erased));
    let shuffled_world = World::load(&shuffled, hash(&shuffled));
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    serde_json::to_writer(
        &mut writer,
        &json!({"kind":"controls","original":hex(&original.digest),
        "erased_loader":format!("{:?}",erased_world.as_ref().map(|_|())),
        "shuffled_loader":format!("{:?}",shuffled_world.as_ref().map(|_|())),
        "counterfactuals_are_not_trained_or_deployed_packs":true,"input_sha256":hex(&hash(&input_bytes))}),
    )?;
    writer.write_all(b"\n")?;
    for query in inputs["queries"].as_array().ok_or("queries")? {
        let mut seeds = [0; NODE_WORDS];
        for v in query["seeds"].as_array().ok_or("seed array")? {
            let i = v.as_u64().ok_or("seed index")? as usize;
            if i >= original.node_count() {
                return Err("input seed outside world".into());
            }
            set(&mut seeds, i);
        }
        let query_hash = hash(query["id"].as_str().ok_or("query id")?.as_bytes());
        for (name, world, pol) in [
            ("original", Some(&original), policy),
            ("erased_coordinates", erased_world.as_ref().ok(), policy),
            ("shuffled_coordinates", shuffled_world.as_ref().ok(), policy),
            (
                "relations_disabled",
                Some(&original),
                Policy {
                    relations: 0,
                    ..policy
                },
            ),
            (
                "past_only",
                Some(&original),
                Policy {
                    direction: Direction::Past,
                    ..policy
                },
            ),
            (
                "future_only",
                Some(&original),
                Policy {
                    direction: Direction::Future,
                    ..policy
                },
            ),
        ] {
            if let Some(world) = world {
                let mut trace = Vec::new();
                let receipt=world.admit_traced(seeds,pol,query_hash,&mut |e|trace.push(json!({"action":e.action,"node":e.node,"edge":e.edge,"neighbor":e.neighbor,"depth":e.depth})))
                    .map_err(|e|format!("admission: {e:?}"))?;
                let record = json!({"kind":"query","id":query["id"],"control":name,"seeds":query["seeds"],
                    "query_sha256":hex(&query_hash),"pack_sha256":hex(&world.digest),"receipt_sha256":hex(&receipt.digest),
                    "policy":{"direction":match pol.direction {Direction::Both=>"both",Direction::Past=>"past",Direction::Future=>"future"},
                        "max_hops":pol.hops,"max_nodes":pol.max_nodes,"relation_mask":pol.relations,"polarity":pol.polarity},
                    "nodes":(0..world.node_count()).filter(|i|bit(&receipt.nodes,*i)).collect::<Vec<_>>(),
                    "edges":(0..world.edge_count()).filter(|i|bit(&receipt.edges,*i)).collect::<Vec<_>>(),
                    "excluded":(0..world.node_count()).filter(|i|bit(&receipt.excluded,*i)).collect::<Vec<_>>(),
                    "frontier":(0..world.node_count()).filter(|i|bit(&receipt.hop_frontier,*i)).collect::<Vec<_>>(),"trace":trace});
                serde_json::to_writer(&mut writer, &record)?;
                writer.write_all(b"\n")?;
            }
        }
    }
    writer.flush()?;
    Ok(())
}
