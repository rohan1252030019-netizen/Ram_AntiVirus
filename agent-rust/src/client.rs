// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic telemetry client with replay protection envelope and HTTPS enforcement.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Insecure HTTP disallowed: {0}. Set AEGIS_ALLOW_INSECURE_HTTP=1 to override.")]
    InsecureHttpDisallowed(String),
    #[error("Cryptographic signing error: {0}")]
    SigningError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryEnvelope {
    pub agent_id: String,
    pub seq: u64,
    pub nonce: String,
    pub timestamp: f64,
    pub signature: String,
    pub payload: serde_json::Value,
}

pub struct AgentClient {
    pub server_url: String,
    pub agent_id: String,
    pub api_key: String,
    seq: AtomicU64,
}

impl AgentClient {
    pub fn new(server_url: &str, agent_id: &str, api_key: &str) -> Result<Self, ClientError> {
        if server_url.starts_with("http://") && !server_url.starts_with("https://") {
            let allow_insecure = std::env::var("RAM_ALLOW_INSECURE_HTTP")
                .or_else(|_| std::env::var("AEGIS_ALLOW_INSECURE_HTTP"))
                .unwrap_or_default() == "1";
            if !allow_insecure {
                return Err(ClientError::InsecureHttpDisallowed(server_url.to_string()));
            }
        }

        Ok(Self {
            server_url: server_url.to_string(),
            agent_id: agent_id.to_string(),
            api_key: api_key.to_string(),
            seq: AtomicU64::new(1),
        })
    }

    pub fn wrap_envelope(&self, payload: serde_json::Value) -> Result<TelemetryEnvelope, ClientError> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let nonce = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let payload_str = serde_json::to_string(&payload)?;
        let msg = format!("{}:{}:{}:{:.3}:{}", self.agent_id, seq, nonce, timestamp, payload_str);

        let mut mac = HmacSha256::new_from_slice(self.api_key.as_bytes())
            .map_err(|e| ClientError::SigningError(e.to_string()))?;
        mac.update(msg.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        Ok(TelemetryEnvelope {
            agent_id: self.agent_id.clone(),
            seq,
            nonce,
            timestamp,
            signature,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insecure_http_handling() {
        std::env::remove_var("AEGIS_ALLOW_INSECURE_HTTP");
        std::env::remove_var("RAM_ALLOW_INSECURE_HTTP");
        let res = AgentClient::new("http://localhost:8000", "test-agent", "secret");
        assert!(res.is_err());

        std::env::set_var("AEGIS_ALLOW_INSECURE_HTTP", "1");
        let res_ok = AgentClient::new("http://localhost:8000", "test-agent", "secret");
        assert!(res_ok.is_ok());
        std::env::remove_var("AEGIS_ALLOW_INSECURE_HTTP");
    }

    #[test]
    fn test_envelope_wrapping_advances_sequence() {
        let client = AgentClient::new("https://localhost:8443", "test-agent", "secret").unwrap();
        let env1 = client.wrap_envelope(serde_json::json!({"test": 1})).unwrap();
        let env2 = client.wrap_envelope(serde_json::json!({"test": 2})).unwrap();
        assert_eq!(env1.seq, 1);
        assert_eq!(env2.seq, 2);
        assert_ne!(env1.nonce, env2.nonce);
        assert!(!env1.signature.is_empty());
    }
}
