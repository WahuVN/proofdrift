#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReasonCode(pub &'static str);

impl ReasonCode {
    pub const POLICY_EXPLICIT_DENY: Self = Self("policy.explicit_deny");
    pub const POLICY_IMPLICIT_DENY: Self = Self("policy.implicit_deny");
    pub const POLICY_APPROVAL_REQUIRED: Self = Self("policy.approval_required");
    pub const POLICY_OBSERVE_ONLY: Self = Self("policy.observe_only");
    pub const CAPABILITY_UNDECLARED: Self = Self("capability.undeclared");
    pub const CAPABILITY_EXPANDED: Self = Self("capability.expanded");
    pub const PROVENANCE_UNVERIFIED: Self = Self("provenance.unverified");
    pub const PROVENANCE_HASH_DRIFT: Self = Self("provenance.hash_drift");
    pub const ENFORCEMENT_UNSUPPORTED: Self = Self("enforcement.unsupported");
    pub const EVIDENCE_INTEGRITY_FAILURE: Self = Self("evidence.integrity_failure");
    pub const TEST_EVIDENCE_INSUFFICIENT: Self = Self("test.insufficient_evidence");
}

pub const KNOWN_REASON_CODES: &[ReasonCode] = &[
    ReasonCode::POLICY_EXPLICIT_DENY,
    ReasonCode::POLICY_IMPLICIT_DENY,
    ReasonCode::POLICY_APPROVAL_REQUIRED,
    ReasonCode::POLICY_OBSERVE_ONLY,
    ReasonCode::CAPABILITY_UNDECLARED,
    ReasonCode::CAPABILITY_EXPANDED,
    ReasonCode::PROVENANCE_UNVERIFIED,
    ReasonCode::PROVENANCE_HASH_DRIFT,
    ReasonCode::ENFORCEMENT_UNSUPPORTED,
    ReasonCode::EVIDENCE_INTEGRITY_FAILURE,
    ReasonCode::TEST_EVIDENCE_INSUFFICIENT,
];

pub fn is_known_reason_code(value: &str) -> bool {
    KNOWN_REASON_CODES.iter().any(|code| code.0 == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicates() {
        let mut values: Vec<_> = KNOWN_REASON_CODES.iter().map(|code| code.0).collect();
        let len = values.len();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), len);
    }
}
