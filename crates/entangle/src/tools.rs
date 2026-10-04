//! MCP tool adapter for the local particle and inbox.

use crate::node::Particle;
use async_trait::async_trait;
use entangle_mcp::{ToolBackend, ToolError};
use serde_json::Value;
use std::sync::Arc;

/// Routes MCP tools to the owning particle.
pub struct ParticleTools {
    particle: Arc<Particle>,
}

impl ParticleTools {
    /// Creates the tool adapter for an active particle.
    pub fn new(particle: Arc<Particle>) -> Self {
        Self { particle }
    }
}

#[async_trait]
impl ToolBackend for ParticleTools {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, ToolError> {
        match tool {
            "find_entangled_particles" => Ok(self.particle.find_particles(&args)),
            "sync_entangled_state" => self.particle.sync_state(args).await.map_err(ToolError),
            "observe_entangled_states" => Ok(self.particle.observe(&args).await),
            _ => Err(ToolError(format!("Unknown tool: {tool}"))),
        }
    }
}
