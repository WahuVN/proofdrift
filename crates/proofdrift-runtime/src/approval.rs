use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub approval_id: String,
    pub scope_digest: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    pub approval_id: String,
    pub token: String,
    pub scope_digest: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("approval challenge not found")]
    NotFound,
    #[error("approval challenge expired")]
    Expired,
    #[error("approval challenge is already approved")]
    AlreadyApproved,
    #[error("approval token is invalid")]
    InvalidToken,
    #[error("approval token does not match the requested action")]
    ScopeMismatch,
    #[error("approval token has already been consumed")]
    Replay,
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
}

#[derive(Debug, Clone)]
enum ApprovalState {
    Pending,
    Approved { token: String, consumed: bool },
}

#[derive(Debug, Clone)]
struct Record {
    scope_digest: String,
    expires_at_ms: u64,
    state: ApprovalState,
}

/// Local one-time approval registry.
///
/// A challenge id is intentionally not an execution token. A trusted local UI/API must
/// call `approve` first; only the returned random token can authorize a retry. This
/// prevents an agent from self-approving merely by reading an APPROVAL_REQUIRED error.
pub struct ApprovalManager {
    ttl_ms: u64,
    clock: Arc<dyn Clock>,
    records: Mutex<HashMap<String, Record>>,
    token_index: Mutex<HashMap<String, String>>,
}

impl ApprovalManager {
    pub fn new(ttl_ms: u64) -> Self {
        Self::with_clock(ttl_ms, Arc::new(SystemClock))
    }

    pub fn with_clock(ttl_ms: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            ttl_ms: ttl_ms.max(1),
            clock,
            records: Mutex::new(HashMap::new()),
            token_index: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_challenge(
        &self,
        scope_digest: impl Into<String>,
    ) -> Result<ApprovalChallenge, ApprovalError> {
        let scope_digest = scope_digest.into();
        let now = self.clock.now_ms();
        let expires_at_ms = now.saturating_add(self.ttl_ms);
        let approval_id = random_id("apr_")?;
        let record = Record {
            scope_digest: scope_digest.clone(),
            expires_at_ms,
            state: ApprovalState::Pending,
        };
        self.records
            .lock()
            .unwrap()
            .insert(approval_id.clone(), record);
        Ok(ApprovalChallenge {
            approval_id,
            scope_digest,
            expires_at_ms,
        })
    }

    pub fn approve(&self, approval_id: &str) -> Result<ApprovalGrant, ApprovalError> {
        let now = self.clock.now_ms();
        let mut records = self.records.lock().unwrap();
        let record = records
            .get_mut(approval_id)
            .ok_or(ApprovalError::NotFound)?;
        if now >= record.expires_at_ms {
            return Err(ApprovalError::Expired);
        }
        if matches!(record.state, ApprovalState::Approved { .. }) {
            return Err(ApprovalError::AlreadyApproved);
        }

        let token = random_id("apt_")?;
        record.state = ApprovalState::Approved {
            token: token.clone(),
            consumed: false,
        };
        self.token_index
            .lock()
            .unwrap()
            .insert(token.clone(), approval_id.to_owned());
        Ok(ApprovalGrant {
            approval_id: approval_id.to_owned(),
            token,
            scope_digest: record.scope_digest.clone(),
            expires_at_ms: record.expires_at_ms,
        })
    }

    pub fn consume(&self, token: &str, scope_digest: &str) -> Result<(), ApprovalError> {
        let approval_id = self
            .token_index
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .ok_or(ApprovalError::InvalidToken)?;
        let now = self.clock.now_ms();
        let mut records = self.records.lock().unwrap();
        let record = records
            .get_mut(&approval_id)
            .ok_or(ApprovalError::InvalidToken)?;
        if now >= record.expires_at_ms {
            return Err(ApprovalError::Expired);
        }
        if record.scope_digest != scope_digest {
            return Err(ApprovalError::ScopeMismatch);
        }
        match &mut record.state {
            ApprovalState::Approved {
                token: expected,
                consumed,
            } if expected == token => {
                if *consumed {
                    return Err(ApprovalError::Replay);
                }
                *consumed = true;
                Ok(())
            }
            _ => Err(ApprovalError::InvalidToken),
        }
    }

    pub fn purge_expired(&self) -> usize {
        let now = self.clock.now_ms();
        let mut records = self.records.lock().unwrap();
        let expired_ids: Vec<String> = records
            .iter()
            .filter(|(_, record)| now >= record.expires_at_ms)
            .map(|(id, _)| id.clone())
            .collect();
        let mut token_index = self.token_index.lock().unwrap();
        for id in &expired_ids {
            if let Some(record) = records.remove(id) {
                if let ApprovalState::Approved { token, .. } = record.state {
                    token_index.remove(&token);
                }
            }
        }
        expired_ids.len()
    }
}

fn random_id(prefix: &str) -> Result<String, ApprovalError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ApprovalError::EntropyUnavailable)?;
    Ok(format!("{prefix}{}", hex::encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);
    impl FakeClock {
        fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }
        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }
    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn challenge_is_not_self_approving_and_token_is_one_time() {
        let clock = Arc::new(FakeClock::new(10));
        let manager = ApprovalManager::with_clock(100, clock);
        let challenge = manager.create_challenge("scope-a").unwrap();
        assert_eq!(
            manager.consume(&challenge.approval_id, "scope-a"),
            Err(ApprovalError::InvalidToken)
        );
        let grant = manager.approve(&challenge.approval_id).unwrap();
        manager.consume(&grant.token, "scope-a").unwrap();
        assert_eq!(
            manager.consume(&grant.token, "scope-a"),
            Err(ApprovalError::Replay)
        );
    }

    #[test]
    fn token_is_bound_to_scope_and_expiry() {
        let clock = Arc::new(FakeClock::new(10));
        let manager = ApprovalManager::with_clock(5, clock.clone());
        let challenge = manager.create_challenge("scope-a").unwrap();
        let grant = manager.approve(&challenge.approval_id).unwrap();
        assert_eq!(
            manager.consume(&grant.token, "scope-b"),
            Err(ApprovalError::ScopeMismatch)
        );
        clock.set(20);
        assert_eq!(
            manager.consume(&grant.token, "scope-a"),
            Err(ApprovalError::Expired)
        );
    }
}
