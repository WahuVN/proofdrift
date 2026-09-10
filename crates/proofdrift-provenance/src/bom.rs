use crate::ProvenanceGraph;
use serde_json::{json, Value};

fn digest_parts(value: Option<&str>) -> Option<(&str, &str)> {
    let raw = value?;
    raw.strip_prefix("sha256:").map(|v| ("SHA-256", v))
}

/// Standards-shaped SPDX 2.3 JSON projection. Unknown provenance remains absent rather than
/// invented; this function projects graph facts and does not certify package authenticity.
pub fn to_spdx_23_json(graph: &ProvenanceGraph, document_name: &str) -> Value {
    let packages: Vec<Value> = graph.artifacts.values().map(|a| {
        let checksums: Vec<Value> = digest_parts(a.content_digest.as_deref())
            .map(|(algorithm, checksum_value)| vec![json!({"algorithm": algorithm, "checksumValue": checksum_value})])
            .unwrap_or_default();
        json!({
            "SPDXID": format!("SPDXRef-{}", sanitize_spdx_id(&a.artifact_id)),
            "name": a.name,
            "versionInfo": a.version,
            "downloadLocation": a.source_uri.as_deref().unwrap_or("NOASSERTION"),
            "checksums": checksums,
            "licenseDeclared": a.metadata.get("license").and_then(Value::as_str).unwrap_or("NOASSERTION")
        })
    }).collect();
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": format!("urn:proofdrift:spdx:{}", crate::adapters::sha256_prefixed(graph.to_json_pretty().unwrap_or_default().as_bytes()).replace(':', "-")),
        "creationInfo": {"creators": ["Tool: provenance-graph"], "created": "1970-01-01T00:00:00Z"},
        "packages": packages
    })
}

/// CycloneDX 1.6 JSON projection for inventory interchange.
pub fn to_cyclonedx_16_json(graph: &ProvenanceGraph) -> Value {
    let components: Vec<Value> = graph.artifacts.values().map(|a| {
        let hashes: Vec<Value> = digest_parts(a.content_digest.as_deref())
            .map(|(_, content)| vec![json!({"alg": "SHA-256", "content": content})])
            .unwrap_or_default();
        json!({
            "type": "library",
            "bom-ref": a.artifact_id,
            "name": a.name,
            "version": a.version,
            "externalReferences": a.source_uri.as_ref().map(|u| vec![json!({"type":"distribution", "url":u})]).unwrap_or_default(),
            "hashes": hashes,
            "licenses": a.metadata.get("license").and_then(Value::as_str).map(|l| vec![json!({"license":{"id":l}})]).unwrap_or_default()
        })
    }).collect();
    json!({"bomFormat":"CycloneDX", "specVersion":"1.6", "version":1, "components":components})
}

fn sanitize_spdx_id(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
