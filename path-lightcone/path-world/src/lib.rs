//! PATHCONE (path-lightcone/PATHCONE-1-PRECOMMIT.md): the world. A trie of the paths seen in
//! training — "only paths trained can pass" (Jesse). **Learned folding** (the FOLD concept): after
//! training, a trie position whose values are volatile (at least `min_distinct` distinct values,
//! none holding more than `max_share` of the visits) folds into a wildcard, so the data itself
//! generalises ephemeral ports and similar; no value is ever written by hand. Matching walks exact
//! children first, then the wildcard, with backtracking; a path matches only at a trained terminal.
//! The fold rule is the caller's (the orchestrator's setting).

use path_sense::{Path, Sym};
use std::collections::{HashMap, HashSet};

/// The wildcard value a folded position takes.
pub const WILD: u128 = u128::MAX;

#[derive(Clone, Copy, Debug)]
pub struct Fold {
    pub min_distinct: usize,
    pub max_share: f64,
}

#[derive(Default, Clone, Debug)]
struct Node {
    children: HashMap<Sym, usize>,
    terminal: bool,
    visits: u64,
}

#[derive(Clone, Debug, Default)]
pub struct World {
    nodes: Vec<Node>,
    /// Every (field, value) trained, for callers choosing untrained values.
    pub seen: HashSet<Sym>,
    pub folds: usize,
}

fn build(paths: &[Path]) -> (Vec<Node>, Vec<Vec<usize>>) {
    let mut nodes = vec![Node::default()];
    let mut trail = Vec::with_capacity(paths.len());
    for p in paths {
        let mut n = 0;
        let mut t = Vec::with_capacity(p.len());
        for s in p {
            t.push(n);
            nodes[n].visits += 1;
            let next = match nodes[n].children.get(s) {
                Some(&c) => c,
                None => {
                    nodes.push(Node::default());
                    let c = nodes.len() - 1;
                    nodes[n].children.insert(*s, c);
                    c
                }
            };
            n = next;
        }
        nodes[n].visits += 1;
        nodes[n].terminal = true;
        trail.push(t);
    }
    (nodes, trail)
}

impl World {
    /// Train from paths, folding volatile positions until none remain (if a rule is given).
    pub fn train(paths: &[Path], fold: Option<Fold>) -> World {
        let mut ps: Vec<Path> = paths.to_vec();
        let seen: HashSet<Sym> = paths.iter().flatten().copied().collect();
        let mut folds = 0;
        loop {
            let (nodes, trail) = build(&ps);
            let Some(rule) = fold else {
                return World { nodes, seen, folds };
            };
            // A node folds when its non-wild children are volatile.
            let mut fold_at: HashSet<usize> = HashSet::new();
            for (id, n) in nodes.iter().enumerate() {
                let kids: Vec<(&Sym, &usize)> = n.children.iter().filter(|(s, _)| s.value != WILD).collect();
                if kids.len() >= rule.min_distinct {
                    let total: u64 = kids.iter().map(|(_, &c)| nodes[c].visits).sum();
                    let top = kids.iter().map(|(_, &c)| nodes[c].visits).max().unwrap_or(0);
                    if (top as f64) <= rule.max_share * total as f64 {
                        fold_at.insert(id);
                    }
                }
            }
            if fold_at.is_empty() {
                return World { nodes, seen, folds };
            }
            folds += fold_at.len();
            for (i, p) in ps.iter_mut().enumerate() {
                for (d, s) in p.iter_mut().enumerate() {
                    if fold_at.contains(&trail[i][d]) {
                        s.value = WILD;
                    }
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    fn walk(&self, n: usize, p: &[Sym]) -> bool {
        let Some((s, rest)) = p.split_first() else {
            return self.nodes[n].terminal;
        };
        let node = &self.nodes[n];
        if let Some(&c) = node.children.get(s) {
            if self.walk(c, rest) {
                return true;
            }
        }
        if let Some(&c) = node.children.get(&Sym { field: s.field, value: WILD }) {
            return self.walk(c, rest);
        }
        false
    }

    /// Does this path follow a trained path (exact or through folded positions)?
    pub fn matches(&self, p: &Path) -> bool {
        !self.nodes.is_empty() && self.walk(0, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[(u8, u128)]) -> Path {
        v.iter().map(|&(f, x)| Sym { field: f, value: x }).collect()
    }

    #[test]
    fn exact_paths_and_learned_folding() {
        // Five flows to service port 53 from five different ephemeral ports.
        let train: Vec<Path> = (0..5).map(|k| p(&[(0, 1), (5, 40000 + k), (6, 53)])).collect();
        let strict = World::train(&train, None);
        assert!(strict.matches(&train[2]) && !strict.matches(&p(&[(0, 1), (5, 41234), (6, 53)])));
        let folded = World::train(&train, Some(Fold { min_distinct: 3, max_share: 0.5 }));
        assert!(folded.matches(&p(&[(0, 1), (5, 41234), (6, 53)])), "the ephemeral source port is learned as volatile");
        assert!(!folded.matches(&p(&[(0, 1), (5, 41234), (6, 54)])), "the service port is not folded");
        assert!(!World::train(&[], None).matches(&train[0]));
    }
}

impl World {
    /// Diagnostic: how many wildcard children each field holds.
    pub fn folded_fields(&self) -> std::collections::BTreeMap<u8, usize> {
        let mut m = std::collections::BTreeMap::new();
        for n in &self.nodes {
            for s in n.children.keys() {
                if s.value == WILD {
                    *m.entry(s.field).or_insert(0) += 1;
                }
            }
        }
        m
    }
}

/// PATHCONE-1 run 2: recurrence folding. A position folds only when its values are mostly
/// **one-burst** — each seen within a single time window and never again — so recurring structure
/// (services, peers, flag sets) stays exact and only genuinely ephemeral values generalise.
#[derive(Clone, Copy, Debug)]
pub struct RecurFold {
    pub min_distinct: usize,
    pub one_burst_fraction: f64,
    pub window_ns: u64,
}

impl World {
    /// Train from (path, capture time) pairs with recurrence folding.
    pub fn train_timed(paths: &[(Path, u64)], fold: RecurFold) -> World {
        let mut ps: Vec<Path> = paths.iter().map(|x| x.0.clone()).collect();
        let times: Vec<u64> = paths.iter().map(|x| x.1).collect();
        let seen: HashSet<Sym> = ps.iter().flatten().copied().collect();
        let mut folds = 0;
        loop {
            let (nodes, trail) = build(&ps);
            // First and last sighting of each child (node, symbol), from the paths through it.
            let mut span: HashMap<(usize, Sym), (u64, u64)> = HashMap::new();
            for (i, p) in ps.iter().enumerate() {
                for (d, s) in p.iter().enumerate() {
                    let e = span.entry((trail[i][d], *s)).or_insert((u64::MAX, 0));
                    e.0 = e.0.min(times[i]);
                    e.1 = e.1.max(times[i]);
                }
            }
            let mut fold_at: HashSet<usize> = HashSet::new();
            for (id, n) in nodes.iter().enumerate() {
                let kids: Vec<&Sym> = n.children.keys().filter(|s| s.value != WILD).collect();
                if kids.len() >= fold.min_distinct {
                    let burst = kids.iter().filter(|s| { let (a, b) = span[&(id, ***s)]; b - a <= fold.window_ns }).count();
                    if burst as f64 >= fold.one_burst_fraction * kids.len() as f64 {
                        fold_at.insert(id);
                    }
                }
            }
            if fold_at.is_empty() {
                return World { nodes, seen, folds };
            }
            folds += fold_at.len();
            for (i, p) in ps.iter_mut().enumerate() {
                for (d, s) in p.iter_mut().enumerate() {
                    if fold_at.contains(&trail[i][d]) {
                        s.value = WILD;
                    }
                }
            }
        }
    }

    fn walk_trace(&self, n: usize, p: &[Sym], trace: &mut Vec<bool>) -> bool {
        let Some((s, rest)) = p.split_first() else {
            return self.nodes[n].terminal;
        };
        let node = &self.nodes[n];
        if let Some(&c) = node.children.get(s) {
            trace.push(true);
            if self.walk_trace(c, rest, trace) {
                return true;
            }
            trace.pop();
        }
        if let Some(&c) = node.children.get(&Sym { field: s.field, value: WILD }) {
            trace.push(false);
            if self.walk_trace(c, rest, trace) {
                return true;
            }
            trace.pop();
        }
        false
    }

    /// For a matching path: per position, whether it matched exactly (true) or by wildcard (false).
    pub fn match_trace(&self, p: &Path) -> Option<Vec<bool>> {
        let mut t = Vec::with_capacity(p.len());
        (!self.nodes.is_empty() && self.walk_trace(0, p, &mut t)).then_some(t)
    }
}

#[cfg(test)]
mod recur_tests {
    use super::*;

    #[test]
    fn recurring_values_stay_exact_one_burst_values_fold() {
        let p = |a: u128, b: u128| vec![Sym { field: 5, value: a }, Sym { field: 6, value: b }];
        // Three services (6, recurring over time) from one-burst ephemeral ports (5).
        let mut train = Vec::new();
        for k in 0..30u64 {
            train.push((p(40000 + k as u128, 5201 + (k % 3) as u128), k * 10_000_000_000));
        }
        let w = World::train_timed(&train, RecurFold { min_distinct: 3, one_burst_fraction: 0.8, window_ns: 1_000_000_000 });
        assert!(w.matches(&p(49999, 5202)), "any ephemeral source port");
        assert!(!w.matches(&p(49999, 5204)), "the services stay exact");
        assert_eq!(w.match_trace(&p(49999, 5202)).unwrap(), vec![false, true]);
    }
}
