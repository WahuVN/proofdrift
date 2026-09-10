use proofdrift_schema::{
    canonical_json_bytes, canonical_sha256, from_json_slice_bounded, ParseError,
};
use serde_json::{json, Map, Number, Value};

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bounded(&mut self, upper: u64) -> u64 {
        self.next() % upper.max(1)
    }
}

fn generated_value(rng: &mut XorShift64, depth: u8) -> Value {
    if depth == 0 {
        return match rng.bounded(5) {
            0 => Value::Null,
            1 => Value::Bool(rng.bounded(2) == 1),
            2 => Value::Number(Number::from(rng.next() as i64)),
            3 => Value::String(format!("ascii-{}-\\\"-\\n", rng.next())),
            _ => Value::String(format!("unicode-{}-\u{1f680}-\u{00e9}", rng.next())),
        };
    }

    match rng.bounded(4) {
        0 => generated_value(rng, 0),
        1 => {
            let len = rng.bounded(5) as usize;
            Value::Array((0..len).map(|_| generated_value(rng, depth - 1)).collect())
        }
        _ => {
            let len = rng.bounded(5) as usize;
            let mut map = Map::new();
            for index in 0..len {
                map.insert(
                    format!("k-{index:02}-{:016x}", rng.next()),
                    generated_value(rng, depth - 1),
                );
            }
            Value::Object(map)
        }
    }
}

#[test]
fn canonical_profile_is_deterministic_and_idempotent_for_generated_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = XorShift64(0x5eed_cafe_d00d_beef);
    for _ in 0..1_000 {
        let value = generated_value(&mut rng, 4);
        let first = canonical_json_bytes(&value);
        let second = canonical_json_bytes(&value);
        assert_eq!(first, second, "same value must produce identical bytes");

        let reparsed: Value = serde_json::from_slice(&first)?;
        assert_eq!(
            first,
            canonical_json_bytes(&reparsed),
            "canonical bytes must be a fixed point"
        );
        assert_eq!(canonical_sha256(&value)?, canonical_sha256(&reparsed)?);
    }
    Ok(())
}

#[test]
fn security_relevant_mutations_change_canonical_digest() -> Result<(), Box<dyn std::error::Error>> {
    let base = json!({
        "request": {"action": "network.connect", "resource": "github.com:443"},
        "policy": {"decision": "ALLOW", "policy_digest": "a".repeat(64)},
        "provenance": {"verified": true, "digest": "b".repeat(64)},
        "enforcement_level": "L1"
    });
    let base_digest = canonical_sha256(&base)?;

    for mutated in [
        json!({
            "request": {"action": "network.connect", "resource": "github.com:443"},
            "policy": {"decision": "DENY", "policy_digest": "a".repeat(64)},
            "provenance": {"verified": true, "digest": "b".repeat(64)},
            "enforcement_level": "L1"
        }),
        json!({
            "request": {"action": "network.connect", "resource": "github.com:443"},
            "policy": {"decision": "ALLOW", "policy_digest": "c".repeat(64)},
            "provenance": {"verified": true, "digest": "b".repeat(64)},
            "enforcement_level": "L1"
        }),
        json!({
            "request": {"action": "network.connect", "resource": "github.com:443"},
            "policy": {"decision": "ALLOW", "policy_digest": "a".repeat(64)},
            "provenance": {"verified": false, "digest": "b".repeat(64)},
            "enforcement_level": "L1"
        }),
        json!({
            "request": {"action": "network.connect", "resource": "github.com:443"},
            "policy": {"decision": "ALLOW", "policy_digest": "a".repeat(64)},
            "provenance": {"verified": true, "digest": "b".repeat(64)},
            "enforcement_level": "L0"
        }),
    ] {
        assert_ne!(base_digest, canonical_sha256(&mutated)?);
    }
    Ok(())
}

#[test]
fn bounded_parser_fails_before_parsing_oversized_payload() {
    let payload = br#"{"value":"synthetic"}"#;
    let result = from_json_slice_bounded::<Value>(payload, payload.len() - 1);
    assert!(matches!(result, Err(ParseError::InputTooLarge { .. })));
}

#[test]
fn malformed_and_truncated_json_never_panics() {
    let samples: &[&[u8]] = &[
        b"",
        b"{",
        b"[1,",
        b"{\"a\":",
        b"{\"a\":\"unterminated}",
        b"\xff\xfe",
        b"null trailing",
        b"[[[[[[[[[[[[[[[[[[[[",
    ];

    for sample in samples {
        let attempt =
            std::panic::catch_unwind(|| from_json_slice_bounded::<Value>(sample, 1024 * 1024));
        assert!(attempt.is_ok(), "bounded parser panicked for {sample:?}");
    }
}
