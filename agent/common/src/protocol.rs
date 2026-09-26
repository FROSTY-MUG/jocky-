//! JOCKY wire protocol types.
//!
//! These structures describe the messages exchanged between an agent and the
//! central manager (registration, heartbeats, job fetch, result upload). They
//! are intentionally plain [`serde`] structs so they can be carried over
//! JSON/gRPC/binary transports unchanged; cryptographic binding is provided by
//! the [`crate::consent`] and [`crate::manifest`] types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::manifest::SignedManifest;

/// Severity classification for a forensic [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    /// Numeric CVSS-like score for quick filtering/aggregation.
    pub fn as_score(&self) -> u8 {
        match self {
            Self::Low => 3,
            Self::Medium => 5,
            Self::High => 7,
            Self::Critical => 9,
        }
    }
}

/// A discrete forensic artifact produced by an agent during a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding (UUID v4).
    pub id: Uuid,
    /// Identifier of the job this finding belongs to.
    pub job_id: String,
    /// Identifier of the agent that produced this finding.
    pub agent_id: String,
    /// Severity classification of the finding.
    pub severity: FindingSeverity,
    /// Short, human-readable title.
    pub title: String,
    /// Longer human-readable description.
    pub description: String,
    /// Arbitrary JSON evidence payload.
    pub evidence_json: String,
    /// MITRE ATT&CK tactic, if applicable (e.g. `"TA0002"`).
    pub mitre_tactic: Option<String>,
    /// MITRE ATT&CK technique, if applicable (e.g. `"T1082"`).
    pub mitre_technique: Option<String>,
    /// Unix timestamp at which the finding was observed.
    pub timestamp: i64,
}

impl Finding {
    /// Create a new finding, stamping a fresh UUID and the current time.
    pub fn new(
        job_id: impl Into<String>,
        agent_id: impl Into<String>,
        severity: FindingSeverity,
        title: impl Into<String>,
        evidence_json: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            job_id: job_id.into(),
            agent_id: agent_id.into(),
            severity,
            title: title.into(),
            description: String::new(),
            evidence_json: evidence_json.into(),
            mitre_tactic: None,
            mitre_technique: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

/// Lifecycle state communicated by an agent in heartbeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    /// Agent is reachable and operating normally.
    Online,
    /// Agent has not checked in within its expected window.
    Offline,
    /// Agent is reachable but one or more collection modules are unhealthy.
    Degraded,
    /// Agent reported it may be under active compromise.
    Compromised,
    /// Agent has been administratively isolated pending review.
    Quarantined,
    /// Agent has been permanently decommissioned.
    Decommissioned,
}

/// Outcome reported by the manager for an uploaded result chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadStatus {
    /// Chunk was accepted but the job is not yet complete.
    Received,
    /// Final chunk accepted and the job is now complete.
    Complete,
    /// Chunk was rejected (e.g. signature failure, replay, tampered).
    Rejected,
}

/// A command the manager may issue to an agent via a heartbeat response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    /// Unique command identifier (UUID v4 as a string).
    pub id: String,
    /// The command to execute.
    pub kind: CommandKind,
    /// Opaque JSON parameters for the command.
    pub params_json: String,
}

/// Kinds of commands the manager can push. Designed to be defensive: no
/// destructive or self-modifying actions are modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    /// Begin or continue the assigned playbook.
    Run,
    /// Temporarily suspend collection until a new command arrives.
    Pause,
    /// Stop the current job and stand down.
    Stop,
    /// Immediately revoke consent and cease all collection.
    Revoke,
}

/// Claims embedded in a manager-issued job token (a signed JWT).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobTokenClaims {
    /// Identifier of the job being authorized.
    pub job_id: String,
    /// Identifier of the agent the token was minted for.
    pub agent_id: String,
    /// Identifier of the team key that signed this token.
    pub team_key_id: String,
    /// Forensic scope the job operates within.
    pub scope: String,
    /// Policy version in effect when the token was issued.
    pub policy_version: String,
    /// Maximum operations permitted under this job token.
    pub max_ops: u64,
    /// Issued-at Unix timestamp.
    pub iat: i64,
    /// Not-before Unix timestamp.
    pub nbf: i64,
    /// Expiry Unix timestamp.
    pub exp: i64,
}

/// Agent -> manager: prove identity and present a signed binary manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Protocol version used by this agent.
    pub protocol_version: String,
    /// Identifier of the registering agent.
    pub agent_id: String,
    /// Identifier of the team key the agent was built/trusting under.
    pub team_key_id: String,
    /// Endpoint hostname.
    pub hostname: String,
    /// Operating-system platform (e.g. `"windows"`, `"linux"`).
    pub platform: String,
    /// Rust target triple the binary was compiled for.
    pub target_triple: String,
    /// Ed25519 public key of the agent; used to verify subsequent signatures.
    pub public_key: Vec<u8>,
    /// Signed attestation of the agent binary (see [`SignedManifest`]).
    pub manifest: SignedManifest,
    /// Proof-of-possession: an Ed25519 signature over
    /// `protocol_version || agent_id || team_key_id || <public_key>` made with
    /// the agent's private key, proving the public key is live-held.
    pub proof: Vec<u8>,
}

/// Manager -> agent: outcome of a registration attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Identifier of the agent, echoed back on success.
    pub agent_id: String,
    /// Resulting status of the agent in the manager's view.
    pub status: AgentStatus,
    /// Signed consent token (JSON) authorizing initial collection, if issued.
    pub consent_token: Option<String>,
    /// Signed job token (JWT) authorizing a specific job, if issued.
    pub job_token: Option<String>,
    /// Manager-local Unix timestamp to align clocks.
    pub server_time: i64,
    /// Human-readable status message.
    pub message: String,
}

/// Agent -> manager: periodic liveness and status update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub job_id: Option<String>,
    pub status: AgentStatus,
    /// Count of operations consumed against the current consent token.
    pub ops_consumed: u64,
    /// Fresh nonce chosen by the agent for this heartbeat.
    pub nonce: String,
    /// Unix timestamp of this heartbeat.
    pub timestamp: i64,
    /// Ed25519 signature over the canonical heartbeat payload.
    pub signature: Vec<u8>,
}

/// Manager -> agent: response to a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub acked: bool,
    pub status: AgentStatus,
    /// Refreshed job token if the manager is issuing a new one.
    pub job_token: Option<String>,
    /// Optional command pushed down with this heartbeat.
    pub command: Option<Command>,
    pub server_time: i64,
}

/// Agent -> manager: request the next pending job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchJobRequest {
    pub agent_id: String,
    pub team_key_id: String,
    /// Ed25519 signature over `agent_id || team_key_id`, proving possession
    /// of the agent's private key.
    pub signature: Vec<u8>,
}

/// Manager -> agent: deliver a job to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchJobResponse {
    /// Identifier of the job being delivered.
    pub job_id: String,
    /// Signed job token (JWT) carrying [`JobTokenClaims`].
    pub job_token: String,
    /// Signed consent token (JSON) authorizing the job's scope.
    pub consent_token: String,
    /// The collection playbook to execute.
    pub playbook: Playbook,
    /// Requested maximum live time, in seconds, for this job.
    pub ttl_secs: i64,
    /// Unix timestamp at which this job delivery expires.
    pub expires_at: i64,
}

/// An ordered collection of playbook steps to execute as a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub name: String,
    pub steps: Vec<PlaybookStep>,
}

/// A single instruction within a [`Playbook`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    /// Collection module to invoke (e.g. `"proc"`, `"net"`, `"hash"`).
    pub module: String,
    /// Operation name within the module (e.g. `"list"`, `"dump"`).
    pub operation: String,
    /// JSON-encoded operation parameters.
    pub params_json: String,
    /// Whether this step requires a fresh, valid consent token to execute.
    pub requires_consent: bool,
}

/// A chunk of job results uploaded by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultChunk {
    pub job_id: String,
    pub agent_id: String,
    /// Zero-based sequence number of this chunk within the job.
    pub seq: u64,
    /// Total number of chunks expected for this job.
    pub total: u64,
    /// Findings produced in this chunk.
    pub findings: Vec<Finding>,
    /// Opaque evidence blob (carved memory/registers/etc.) for this chunk.
    pub evidence_blob: Vec<u8>,
    /// Ed25519 signature over the canonical chunk payload.
    pub signature: Vec<u8>,
    /// Unix timestamp at which the chunk was sealed.
    pub timestamp: i64,
}

/// Manager -> agent: outcome of an uploaded result chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub job_id: String,
    /// Number of chunks accepted so far for this job.
    pub accepted_chunks: u64,
    pub status: UploadStatus,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serializes_and_stamps_uuid() {
        let f = Finding::new(
            "job-123",
            "agent-001",
            FindingSeverity::High,
            "Suspicious process",
            r#"{"name":"evil.exe","pid":31337}"#,
        );
        assert!(!f.id.is_nil());
        let json = serde_json::to_string(&f).expect("finding serializes");
        let back: Finding = serde_json::from_str(&json).expect("finding deserializes");
        assert_eq!(back.severity, FindingSeverity::High);
        assert_eq!(back.evidence_json, r#"{"name":"evil.exe","pid":31337}"#);
    }

    #[test]
    fn severity_orders_correctly() {
        assert!(FindingSeverity::Low < FindingSeverity::Medium);
        assert!(FindingSeverity::Medium < FindingSeverity::High);
        assert!(FindingSeverity::High < FindingSeverity::Critical);
        assert_eq!(FindingSeverity::Critical.as_score(), 9);
    }

    #[test]
    fn register_request_embeds_signed_manifest() {
        use crate::constants;
        use ed25519_dalek::{Signature, Signer, SigningKey};

        let mut seed = [0u8; constants::ED25519_KEY_LEN];
        seed[0] = 0x9d;
        let signing_key = SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key().to_bytes();

        let mut manifest = SignedManifest::new(
            "team-1",
            "build-abc",
            constants::POLICY_VERSION,
            42,
            "aabbccdd",
            2048,
            "aarch64-unknown-linux-gnu",
        );
        manifest.sign(&signing_key);

        let proof: Signature = signing_key.sign(b"proof-of-possession");

        let req = RegisterRequest {
            protocol_version: constants::PROTOCOL_VERSION.to_string(),
            agent_id: "agent-001".to_string(),
            team_key_id: "team-1".to_string(),
            hostname: "workstation-1".to_string(),
            platform: "linux".to_string(),
            target_triple: "aarch64-unknown-linux-gnu".to_string(),
            public_key: vk.to_vec(),
            manifest,
            proof: proof.to_bytes().to_vec(),
        };

        let json = serde_json::to_string(&req).expect("register request serializes");
        let back: RegisterRequest =
            serde_json::from_str(&json).expect("register request deserializes");
        assert!(back.manifest.verify(&vk).is_ok());
        assert_eq!(back.agent_id, "agent-001");
    }

    #[test]
    fn enums_round_trip_through_json() {
        let json = serde_json::to_string(&AgentStatus::Compromised).unwrap();
        let s: AgentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, AgentStatus::Compromised);

        let json = serde_json::to_string(&UploadStatus::Complete).unwrap();
        let u: UploadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(u, UploadStatus::Complete);

        let json = serde_json::to_string(&CommandKind::Run).unwrap();
        let c: CommandKind = serde_json::from_str(&json).unwrap();
        assert_eq!(c, CommandKind::Run);
    }
}