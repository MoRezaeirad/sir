//! sir-core-eval: JSON-in / JSON-out subprocess interface to the Rust decision kernel.
//!
//! Input (stdin, one JSON object per line):
//!   {"case_id":"...", "mode":"hook_gate", "signals":[...],
//!    "evasion_flags":{...}, "prior_taint":[], "provider_capabilities":[]}
//!
//! Output (stdout, one JSON line per input):
//!   {"verdict":"deny","decision_class":"deny_now","enforceability":"enforces",
//!    "attribution":"high","policy_rules":["deny-agent-credential-read"],
//!    "effects":[{"type":"block","required":true,"fail_closed":true}],
//!    "action_type":"file_read","sensitivity":"credential","new_taint":["credential_access"]}
//!
//! Exit code: 0 on success, 1 on parse/IO error.

use mister_shared::{parse_json, JsonValue};
use sir_core::{
    evaluate, ActionClaim, ActionTarget, EvaluationInput, EvasionFlags, PlannedEffect, Signal,
    SignalSource,
};
use std::io::{self, BufRead, Write};

fn get_bool(obj: Option<&JsonValue>, key: &str) -> bool {
    obj.and_then(|o: &JsonValue| o.get(key))
        .and_then(|v: &JsonValue| v.as_bool())
        .unwrap_or(false)
}

fn get_str(obj: Option<&JsonValue>, key: &str) -> String {
    obj.and_then(|o: &JsonValue| o.get(key))
        .and_then(|v: &JsonValue| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn str_val(v: Option<&JsonValue>) -> String {
    v.and_then(|x: &JsonValue| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn parse_input(raw: &str) -> Result<EvaluationInput, String> {
    let val = parse_json(raw).map_err(|e| format!("json parse error: {e:?}"))?;

    let mode = str_val(val.get("mode"));
    let case_id = str_val(val.get("case_id"));

    // evasion_flags
    let ef = val.get("evasion_flags");
    let evasion = EvasionFlags {
        span_stripped: get_bool(ef, "span_stripped"),
        span_forged: get_bool(ef, "span_forged"),
        detached_child: get_bool(ef, "detached_child"),
        hook_missing: get_bool(ef, "hook_missing"),
        required_effect_unavail: get_bool(ef, "required_effect_unavailable"),
        fail_closed: get_bool(ef, "fail_closed"),
    };

    // signals array
    let mut signals: Vec<Signal> = Vec::new();
    if let Some(arr) = val.get("signals").and_then(|v: &JsonValue| v.as_array()) {
        for sig in arr {
            let src = sig.get("source");
            let ac = sig.get("action_claim");
            let tgt = ac.and_then(|a: &JsonValue| a.get("target"));
            let actor = sig.get("actor_claim");
            signals.push(Signal {
                source: SignalSource {
                    reliability: get_str(src, "reliability"),
                    timing: get_str(src, "timing"),
                },
                action_claim: ActionClaim {
                    action_type: get_str(ac, "type"),
                    target: ActionTarget {
                        display: get_str(tgt, "display"),
                        sensitivity: get_str(tgt, "sensitivity"),
                    },
                },
                actor_kind: get_str(actor, "kind"),
            });
        }
    }

    // prior_taint
    let prior_taint: Vec<String> = val
        .get("prior_taint")
        .and_then(|v: &JsonValue| v.as_array())
        .map(|arr: &[JsonValue]| {
            arr.iter()
                .filter_map(|v: &JsonValue| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // provider_capabilities
    let provider_capabilities: Vec<String> = val
        .get("provider_capabilities")
        .and_then(|v: &JsonValue| v.as_array())
        .map(|arr: &[JsonValue]| {
            arr.iter()
                .filter_map(|v: &JsonValue| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let resolved_actor_kind = str_val(val.get("resolved_actor_kind"));

    // policy_verdicts — advisory verdicts from policy providers (OPA, Cedar, etc.)
    let policy_verdicts: Vec<sir_core::PolicyVerdict> = val
        .get("policy_verdicts")
        .and_then(|v: &JsonValue| v.as_array())
        .map(|arr: &[JsonValue]| {
            arr.iter()
                .map(|pv: &JsonValue| sir_core::PolicyVerdict {
                    provider: str_val(pv.get("provider")),
                    verdict: str_val(pv.get("verdict")),
                    rules_matched: pv
                        .get("rules_matched")
                        .and_then(|v: &JsonValue| v.as_array())
                        .map(|a: &[JsonValue]| {
                            a.iter()
                                .filter_map(|r: &JsonValue| r.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    reason: str_val(pv.get("reason")),
                    // Default to advisory=true when absent: external verdicts are
                    // advisory by contract. An explicit is_advisory:false is honored
                    // (and then ignored by composition, which only acts on advisory).
                    is_advisory: pv
                        .get("is_advisory")
                        .and_then(|v: &JsonValue| v.as_bool())
                        .unwrap_or(true),
                })
                .collect()
        })
        .unwrap_or_default();

    let provider_enforcement = str_val(val.get("provider_enforcement"));

    // provider_enforced_actions (item 8): action types the provider enforces.
    let provider_enforced_actions: Vec<String> = val
        .get("provider_enforced_actions")
        .and_then(|v: &JsonValue| v.as_array())
        .map(|arr: &[JsonValue]| {
            arr.iter()
                .filter_map(|v: &JsonValue| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(EvaluationInput {
        case_id,
        mode,
        signals,
        evasion,
        prior_taint,
        provider_capabilities,
        resolved_actor_kind,
        policy_verdicts,
        provider_enforcement,
        provider_enforced_actions,
    })
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn effect_to_json(e: &PlannedEffect) -> String {
    format!(
        r#"{{"type":{},"required":{},"fail_closed":{}}}"#,
        json_str(&e.effect_type),
        e.required,
        e.fail_closed,
    )
}

fn output_to_json(out: &sir_core::EvaluationOutput) -> String {
    let rules = out
        .policy_rules
        .iter()
        .map(|r| json_str(r))
        .collect::<Vec<_>>()
        .join(",");
    let effects = out
        .effects
        .iter()
        .map(effect_to_json)
        .collect::<Vec<_>>()
        .join(",");
    let taint = out
        .new_taint
        .iter()
        .map(|t| json_str(t))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        concat!(
            r#"{{"verdict":{v},"decision_class":{dc},"enforceability":{enf},"#,
            r#""attribution":{attr},"spoofing_risk":{sr},"policy_rules":[{rules}],"effects":[{effects}],"#,
            r#""action_type":{at},"sensitivity":{sens},"new_taint":[{taint}]}}"#
        ),
        v = json_str(&out.verdict),
        dc = json_str(&out.decision_class),
        enf = json_str(&out.enforceability),
        attr = json_str(&out.attribution),
        sr = json_str(&out.spoofing_risk),
        rules = rules,
        effects = effects,
        at = json_str(&out.action_type),
        sens = json_str(&out.sensitivity),
        taint = taint,
    )
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let raw = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sir-core-eval: read error: {e}");
                std::process::exit(1);
            }
        };
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            continue;
        }
        match parse_input(&raw) {
            Ok(input) => {
                let result = evaluate(&input);
                writeln!(out, "{}", output_to_json(&result)).unwrap();
            }
            Err(e) => {
                eprintln!("sir-core-eval: {e}");
                std::process::exit(1);
            }
        }
    }
}
