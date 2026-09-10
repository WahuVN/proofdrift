use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Active,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionLifecycle {
    pub session_id: String,
    pub state: SessionState,
}

impl SessionLifecycle {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            state: SessionState::Created,
        }
    }

    pub fn transition(&mut self, next: SessionState) -> Result<(), TransitionError> {
        let allowed = matches!(
            (self.state, next),
            (SessionState::Created, SessionState::Active)
                | (SessionState::Created, SessionState::Failed)
                | (SessionState::Active, SessionState::Completed)
                | (SessionState::Active, SessionState::Failed)
                | (SessionState::Active, SessionState::RolledBack)
                | (SessionState::Failed, SessionState::RolledBack)
        );
        if !allowed {
            return Err(TransitionError {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid session state transition {from:?} -> {to:?}")]
pub struct TransitionError {
    pub from: SessionState,
    pub to: SessionState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_accepts_documented_paths_and_rejects_terminal_reopen() {
        let mut lifecycle = SessionLifecycle::new("s1");
        lifecycle.transition(SessionState::Active).unwrap();
        lifecycle.transition(SessionState::Completed).unwrap();
        assert!(lifecycle.transition(SessionState::Active).is_err());
    }

    #[test]
    fn failed_session_can_be_rolled_back_but_not_completed() {
        let mut lifecycle = SessionLifecycle::new("s1");
        lifecycle.transition(SessionState::Failed).unwrap();
        assert!(lifecycle.transition(SessionState::Completed).is_err());
        lifecycle.transition(SessionState::RolledBack).unwrap();
    }
}
