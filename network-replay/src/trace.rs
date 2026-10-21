//! Serialization stays outside the no_std observer and admission engine.
use super::*;
use kernel_lightcone::AdmissionStep;
use network_lightcone_observer::ObserverStep;

pub struct FrameTrace {
    enabled: bool,
    started: Instant,
    pub events: Vec<Value>,
}
impl FrameTrace {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            started: Instant::now(),
            events: Vec::new(),
        }
    }
    pub fn record(&mut self, actor: &str, detail: Value) {
        if self.enabled {
            self.events.push(json!({"ordinal": self.events.len(), "elapsed_us": self.started.elapsed().as_micros() as u64,
                                   "actor": actor, "detail": detail}));
        }
    }
    pub fn observer(&mut self, event: ObserverStep) {
        let detail = match event {
            ObserverStep::Enter {
                stage,
                offset,
                length,
            } => json!({"action":"enter", "stage":stage,"offset":offset,"length":length}),
            ObserverStep::Field { name, value } => {
                json!({"action":"field","name":name,"value":value})
            }
            ObserverStep::Check {
                rejection_reason,
                passed,
            } => json!({"action":"check","rejection_reason":rejection_reason,"passed":passed}),
            ObserverStep::Seed { node } => json!({"action":"seed_added","node":node}),
            ObserverStep::Discard { reason, seeds } => {
                json!({"action":"seeds_discarded","reason":reason,"seed_mask":seeds})
            }
            ObserverStep::Finish {
                kind,
                reason,
                seeds,
            } => {
                json!({"action":"complete","kind":kind_label(kind),"reason":reason,"seed_mask":seeds})
            }
        };
        self.record("observer", detail);
    }
    pub fn admission(&mut self, event: AdmissionStep) {
        self.record(
            "admission",
            json!({"action":event.action,"node":event.node,"edge":event.edge,
                                       "neighbor":event.neighbor,"depth":event.depth}),
        );
    }
}

pub fn world_snapshot(context: &Context) -> Result<Value> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for i in 0..context.world.node_count() {
        let coords: std::result::Result<Vec<_>, _> =
            (0..52).map(|d| context.world.coordinate(i, d)).collect();
        let coords = coords.map_err(|e| invalid(format!("coordinate {i}: {e:?}")))?;
        nodes.push(json!({"index":i,"record":serde_json::from_str::<Value>(context.world.node_json(i).map_err(|e|invalid(format!("node {i}: {e:?}")))?)?,
                          "full_48d_quantized":coords[..48],"observer_4d_quantized":coords[48..]}));
    }
    for i in 0..context.world.edge_count() {
        let e = context
            .world
            .edge(i)
            .map_err(|e| invalid(format!("edge {i}: {e:?}")))?;
        edges.push(json!({"index":i,"source":e.source,"target":e.target,"relation":e.relation,"polarity":e.polarity,
                          "record":serde_json::from_str::<Value>(context.world.edge_json(i).map_err(|e|invalid(format!("edge metadata: {e:?}")))?)?}));
    }
    Ok(
        json!({"schema":1,"pack_sha256":context.pack_sha256,"world_source_sha256":context.world_sha256,
        "nodes":nodes,"edges":edges,"coordinate_scale":1000000,"policy":policy_json(context.policy),
        "admission_driver":"exact typed graph and policy; coordinates are validated at load, not consulted by admit",
        "observer_axes":["x","y","z","w"],"observer_controls_admission":false,
        "edge_conditions_evaluated":false,"flow_state_tracked":false,"payload_semantics_evaluated":false,
        "conditional_mechanisms_are_not_observed_consequences":true}),
    )
}

pub struct Lifecycle {
    writer: File,
    sequence: u64,
}
impl Lifecycle {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            writer: fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
            sequence: 0,
        })
    }
    pub fn record(&mut self, stage: &str, detail: Value) -> Result<()> {
        let event = json!({"sequence":self.sequence,"stage":stage,"unix_ns":SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64,"detail":detail});
        serde_json::to_writer(&mut self.writer, &event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.sequence += 1;
        Ok(())
    }
}
