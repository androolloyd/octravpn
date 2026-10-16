// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_graph validation, multiplication depth and canonical live graph reduction.
//! Reduction merges edges only when the profile's edge capacity is exceeded.
use super::Natural;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sign {
    Pos,
    Neg,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Base,
    Prod(Natural, Natural),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    tag: Natural,
    rule: Rule,
}
impl Layer {
    pub fn tag(&self) -> Natural {
        self.tag
    }
    pub fn rule(&self) -> Rule {
        self.rule
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    layer: Natural,
    index: Natural,
    sign: Sign,
    weight: Vec<BigInt>,
    sigma: Vec<bool>,
}
impl Edge {
    pub fn layer(&self) -> Natural {
        self.layer
    }
    pub fn index(&self) -> Natural {
        self.index
    }
    pub fn sign(&self) -> Sign {
        self.sign
    }
    pub fn weight(&self) -> &[BigInt] {
        &self.weight
    }
    pub fn sigma(&self) -> &[bool] {
        &self.sigma
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    basis: Natural,
    slots: Natural,
    sigma: Natural,
    edge_capacity: BigInt,
}
impl Config {
    pub fn new(
        basis: Natural,
        slots: Natural,
        sigma: Natural,
        edge_capacity: BigInt,
    ) -> Result<Self, Error> {
        if basis.get() == 0
            || slots.get() == 0
            || sigma.get() == 0
            || edge_capacity <= BigInt::zero()
        {
            return Err(Error::Config);
        }
        Ok(Self {
            basis,
            slots,
            sigma,
            edge_capacity,
        })
    }
    pub fn basis(&self) -> Natural {
        self.basis
    }
    pub fn slots(&self) -> Natural {
        self.slots
    }
    pub fn sigma(&self) -> Natural {
        self.sigma
    }
    pub fn edge_capacity(&self) -> &BigInt {
        &self.edge_capacity
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    layers: Vec<Layer>,
    edges: Vec<Edge>,
}
impl Graph {
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    graph: Graph,
    merged: bool,
    layer_count: BigInt,
    edge_count: BigInt,
    removed: BigInt,
}
impl Info {
    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn merged(&self) -> bool {
        self.merged
    }
    pub fn layer_count(&self) -> &BigInt {
        &self.layer_count
    }
    pub fn edge_count(&self) -> &BigInt {
        &self.edge_count
    }
    pub fn removed(&self) -> &BigInt {
        &self.removed
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config,
    Layer,
    Edge,
    Shape,
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Config => b"graph profile is invalid".to_vec(),
            Self::Layer => b"graph layer is invalid".to_vec(),
            Self::Edge => b"graph edge is invalid".to_vec(),
            Self::Shape => b"graph shape is invalid".to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn prime() -> BigInt {
    (BigInt::one() << 127_usize) - BigInt::one()
}
fn field(value: &BigInt) -> bool {
    value >= &BigInt::zero() && value < &prime()
}
pub fn base(tag: Natural) -> Layer {
    Layer {
        tag,
        rule: Rule::Base,
    }
}
pub fn prod(tag: Natural, left: Natural, right: Natural) -> Layer {
    Layer {
        tag,
        rule: Rule::Prod(left, right),
    }
}
pub fn edge(
    layer: Natural,
    index: Natural,
    sign: Sign,
    weight: Vec<BigInt>,
    sigma: Vec<bool>,
) -> Result<Edge, Error> {
    if !weight.iter().all(field) {
        return Err(Error::Edge);
    }
    Ok(Edge {
        layer,
        index,
        sign,
        weight,
        sigma,
    })
}
pub fn graph(layers: Vec<Layer>, edges: Vec<Edge>) -> Graph {
    Graph { layers, edges }
}
fn count(value: usize) -> Option<Natural> {
    Natural::from_u32(u32::try_from(value).ok()?)
}
fn layer_ok(at: Natural, value: &Layer) -> bool {
    match value.rule {
        Rule::Base => true,
        Rule::Prod(left, right) => left < at && right < at,
    }
}
pub fn valid(config: &Config, value: &Graph) -> bool {
    let Some(layers) = count(value.layers.len()) else {
        return false;
    };
    value
        .layers
        .iter()
        .enumerate()
        .all(|(at, value)| count(at).is_some_and(|at| layer_ok(at, value)))
        && value.edges.iter().all(|edge| {
            edge.layer < layers
                && edge.index < config.basis
                && edge.weight.len() == config.slots.get() as usize
                && edge.sigma.len() == config.sigma.get() as usize
                && edge.weight.iter().all(field)
        })
}
pub fn mul_depth(value: &Graph) -> Result<Natural, Error> {
    count(value.layers.len()).ok_or(Error::Layer)?;
    let mut depths = Vec::<u32>::with_capacity(value.layers.len());
    let mut peak = 0;
    for (at, layer) in value.layers.iter().enumerate() {
        if !layer_ok(count(at).ok_or(Error::Layer)?, layer) {
            return Err(Error::Layer);
        }
        let depth = match layer.rule {
            Rule::Base => 0,
            Rule::Prod(left, right) => {
                let left = depths.get(left.get() as usize).ok_or(Error::Layer)?;
                let right = depths.get(right.get() as usize).ok_or(Error::Layer)?;
                1 + (*left).max(*right)
            }
        };
        depths.push(depth);
        peak = peak.max(depth);
    }
    Natural::from_u32(peak).ok_or(Error::Layer)
}
fn merge(edges: &[Edge]) -> Vec<Edge> {
    let prime = prime();
    let mut cells = BTreeMap::<(Natural, Natural, Sign), (Vec<BigInt>, Vec<bool>)>::new();
    for edge in edges {
        let key = (edge.layer, edge.index, edge.sign);
        match cells.get_mut(&key) {
            None => {
                cells.insert(key, (edge.weight.clone(), edge.sigma.clone()));
            }
            Some((weight, sigma)) => {
                for (prior, next) in weight.iter_mut().zip(&edge.weight) {
                    *prior = (&*prior + next) % &prime;
                }
                for (prior, next) in sigma.iter_mut().zip(&edge.sigma) {
                    *prior ^= *next;
                }
            }
        }
    }
    cells
        .into_iter()
        .filter_map(|((layer, index, sign), (weight, sigma))| {
            (weight.iter().any(|value| !value.is_zero()) || sigma.iter().any(|value| *value))
                .then_some(Edge {
                    layer,
                    index,
                    sign,
                    weight,
                    sigma,
                })
        })
        .collect()
}
fn compact(layers: &[Layer], mut edges: Vec<Edge>) -> Option<Graph> {
    let mut live = vec![false; layers.len()];
    for edge in &edges {
        *live.get_mut(edge.layer.get() as usize)? = true;
    }
    // Product parents precede their child. A reverse pass reaches every live ancestor.
    for at in (0..layers.len()).rev() {
        if live[at] {
            if let Rule::Prod(left, right) = layers[at].rule {
                *live.get_mut(left.get() as usize)? = true;
                *live.get_mut(right.get() as usize)? = true;
            }
        }
    }
    let mut ids = vec![None; layers.len()];
    let mut kept = Vec::new();
    for (at, layer) in layers.iter().enumerate() {
        if !live[at] {
            continue;
        }
        ids[at] = Some(count(kept.len())?);
        let rule = match layer.rule {
            Rule::Base => Rule::Base,
            Rule::Prod(left, right) => Rule::Prod(
                *ids.get(left.get() as usize)?.as_ref()?,
                *ids.get(right.get() as usize)?.as_ref()?,
            ),
        };
        kept.push(Layer {
            tag: layer.tag,
            rule,
        });
    }
    for edge in &mut edges {
        edge.layer = *ids.get(edge.layer.get() as usize)?.as_ref()?;
    }
    Some(Graph {
        layers: kept,
        edges,
    })
}
pub fn norm(config: &Config, value: &Graph) -> Result<Info, Error> {
    if !valid(config, value) {
        return Err(Error::Shape);
    }
    let merged = config.edge_capacity < BigInt::from(value.edges.len());
    let edges = if merged {
        merge(&value.edges)
    } else {
        value.edges.clone()
    };
    let graph = compact(&value.layers, edges).ok_or(Error::Shape)?;
    if !valid(config, &graph) {
        return Err(Error::Shape);
    }
    Ok(Info {
        layer_count: graph.layers.len().into(),
        edge_count: graph.edges.len().into(),
        removed: (value.layers.len() - graph.layers.len()).into(),
        graph,
        merged,
    })
}
