//! Composable inspection pipeline.

use crate::{decision::Decision, layer::PacketView, qos::QosFields};

/// A single inspection stage in the pipeline.
///
/// Each stage receives a zero-copy view of the packet and returns a verdict.
/// Stages are called in order; the first non-`Forward` verdict short-circuits
/// the remaining stages.
pub trait Stage {
    /// Inspect the packet and return a verdict.
    fn inspect(&mut self, pkt: &PacketView<'_>, qos: QosFields) -> Decision;
}

/// A fixed-capacity, composable packet inspection pipeline.
///
/// Stages are stored as trait objects in a `heapless::Vec`. The pipeline
/// runs each stage in order and short-circuits on the first non-`Forward`
/// verdict.
///
/// `N` is the maximum number of stages (should be small, e.g. 8–16).
pub struct Pipeline<const N: usize> {
    stages: heapless::Vec<&'static mut dyn Stage, N>,
}

impl<const N: usize> Pipeline<N> {
    /// Creates an empty pipeline.
    pub const fn new() -> Self {
        Self { stages: heapless::Vec::new() }
    }

    /// Adds a stage to the pipeline.
    ///
    /// Stages are evaluated in insertion order. Returns `Err` if the
    /// pipeline is full.
    pub fn add_stage(&mut self, stage: &'static mut dyn Stage) -> Result<(), &'static str> {
        self.stages.push(stage).map_err(|_| "pipeline full")
    }

    /// Run all stages against `pkt`.
    ///
    /// Returns the first non-`Forward` verdict, or `Forward` if all stages
    /// pass. The `IDS mode` honour contract: if the operator mode is
    /// `AlertOnly`, any `Drop` returned by a stage is converted to `Alert`.
    pub fn run(&mut self, pkt: &PacketView<'_>, qos: QosFields, ids_mode: bool) -> Decision {
        for stage in self.stages.iter_mut() {
            let d = stage.inspect(pkt, qos);
            match d {
                Decision::Forward => continue,
                Decision::Drop if ids_mode => return Decision::Alert,
                other => return other,
            }
        }
        Decision::Forward
    }
}

impl<const N: usize> Default for Pipeline<N> {
    fn default() -> Self {
        Self::new()
    }
}
