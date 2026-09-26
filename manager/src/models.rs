use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModel {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub status: String,
    pub registered_at: i64,
}
