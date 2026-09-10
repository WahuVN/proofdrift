use proofdrift_policy::{built_in_policy_pack, PolicyEngine, PolicyRequest};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let engine = PolicyEngine::default();
    let pack = engine
        .compile_cached(built_in_policy_pack("read-only-audit").expect("built-in pack"))
        .expect("compile policy pack");
    let request = PolicyRequest::new("bench-agent", "fs.read", "C:/repo/src/lib.rs");
    let iterations = 50_000u64;

    for _ in 0..1_000 {
        black_box(
            engine
                .evaluate(&pack, &request, None)
                .expect("warmup evaluation"),
        );
    }

    let started = Instant::now();
    for _ in 0..iterations {
        black_box(
            engine
                .evaluate(&pack, &request, None)
                .expect("policy evaluation"),
        );
    }
    let elapsed = started.elapsed();
    let ns_per_eval = elapsed.as_nanos() / u128::from(iterations);
    println!("policy_eval iterations={iterations} elapsed={elapsed:?} ns_per_eval={ns_per_eval}");
}
