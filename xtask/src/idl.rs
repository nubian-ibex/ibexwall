// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Minimal varlink IDL renderer.
//!
//! The source of truth for types is `ibexwall-proto`. This module converts
//! the JSON Schema of each IDL-facing type to varlink type syntax. Methods
//! and errors have no schema representation and are maintained as text
//! blocks here; the drift check still covers whole files, so any
//! regeneration mismatch fails CI.
//!
//! Conversion subset (deliberately small; new types must stay inside it):
//! string enums, scalars, `[]T`, `[string]T` dicts, `?T` optionals via
//! nullable unions, `$ref` to sibling types, and free-form `object`.
//! Anything else (e.g. `oneOf` tagged unions like `Op`) is exported as a
//! JSON Schema only, never to the IDL.

use anyhow::{Context, Result, bail};
use serde_json::Value;

pub fn interfaces() -> Result<Vec<(&'static str, String)>> {
    Ok(vec![
        (
            "com.ibexwall.Core.varlink",
            render_interface("com.ibexwall.Core", CORE_TYPES, CORE_METHODS)?,
        ),
        (
            "com.ibexwall.Plugin.varlink",
            render_interface("com.ibexwall.Plugin", &[], PLUGIN_METHODS)?,
        ),
        (
            "com.ibexwall.Policy.varlink",
            render_interface("com.ibexwall.Policy", &[], POLICY_METHODS)?,
        ),
    ])
}

const CORE_TYPES: &[&str] = &[
    "Severity",
    "Info",
    "ProtectionStatus",
    "Posture",
    "Reference",
    "Remediation",
    "FindingStatus",
    "Finding",
    "PluginOrigin",
    "PluginInfo",
    "RiskFlag",
    "Reversible",
    "OpPreview",
    "Plan",
    "TransactionState",
    "Transaction",
    "HistoryEntry",
    "Event",
    "ProposalStatus",
    "Proposal",
];

const CORE_METHODS: &str = "\
# Client-facing API. Subscribe is called with \"more\": true for streaming.
method GetInfo() -> (info: Info)
method GetPosture() -> (posture: Posture)
method ListPlugins() -> (plugins: []PluginInfo)
method SetPluginEnabled(id: string, enabled: bool) -> (plan: ?Plan)
method RunChecks(plugin: ?string) -> (findings: []Finding)
method ListFindings(plugin: ?string, min_severity: ?Severity) -> (findings: []Finding)
method GetConfig(plugin: string) -> (effective: object, layers: object, locks: []string)
method PlanChange(plugin: string, patch: object) -> (plan: Plan)
method Apply(plan_id: string, confirm_timeout_s: ?int) -> (transaction: Transaction)
method Confirm(transaction_id: string) -> ()
method Rollback(target: string) -> (transaction: Transaction)
method History(limit: ?int, before: ?int) -> (entries: []HistoryEntry)
method Subscribe(sources: ?[]string) -> (event: Event)
method ListProposals(status: ?string) -> (proposals: []Proposal)
method CreateProposal(plugin: string, patch: object, justification: string) -> (proposal: Proposal)
method DecideProposal(id: string, decision: string, patch: ?object) -> (transaction: ?Transaction)

error PermissionDenied (action: string)
error NotFound (kind: string, id: string)
error Locked (keys: []string, source: string)
error PlanExpired (plan_id: string)
error PlanStale (plan_id: string)
error Conflict (reason: string)
error InvalidArgument (field: string, reason: string)
";

const PLUGIN_METHODS: &str = "\
# Plugin-side interface; ops/objects are validated against plugin.toml
# privileges by the core (Op travels as JSON Schema, see spec/schemas).
method Describe() -> (manifest: object, api: int)
method Check(config: object) -> (findings: []object)
method Plan(config: object, previous: ?object) -> (ops: []object, notes: []string, may_affect_keys: []string)
method Verify(transaction_id: string, ops: []object) -> (ok: bool, details: []string)
method Monitor() -> (event: object)
method Reconcile(desired: object) -> (applied: bool, details: []string)
";

const POLICY_METHODS: &str = "\
# Managed-mode policy provider contract; access is restricted to the
# principal authorized for com.ibexwall.policy.provider.
method ApplyBundle(bundle: object) -> (version: int, locks: []string)
method GetEffective() -> (config: object, locks: []string, sources: [string]string)
method BuildReport(kind: string) -> (report: object)
method UseBreakGlass(code: string) -> (unlocked: []string, expires_at: string)

error InvalidSignature (key_id: string)
error Expired (expires_at: string)
error VersionRollback (current: int, offered: int)
";

fn render_interface(name: &str, types: &[&str], methods: &str) -> Result<String> {
    let mut out = format!("interface {name}\n\n");
    for ty in types {
        out.push_str(&render_type(ty)?);
    }
    out.push('\n');
    out.push_str(methods);
    Ok(out)
}

fn schema_of(name: &str) -> Result<Value> {
    ibexwall_proto::export::schemas()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
        .with_context(|| format!("schema for `{name}` is not exported by ibexwall-proto"))
}

fn render_type(name: &str) -> Result<String> {
    let schema = schema_of(name)?;
    if let Some(variants) = schema.get("enum").and_then(Value::as_array) {
        let list: Vec<String> = variants
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        return Ok(format!("type {name} ({})\n", list.join(", ")));
    }
    let empty = serde_json::Map::new();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let required = schema.get("required").and_then(Value::as_array);
    let is_required = |field: &str| -> bool {
        required.is_some_and(|r| r.iter().any(|v| v.as_str() == Some(field)))
    };
    let mut fields: Vec<String> = Vec::new();
    for (field, sub) in props {
        let mut ty =
            convert(sub).with_context(|| format!("converting field {name}.{field} to varlink"))?;
        if !ty.starts_with('?') && !is_required(field) {
            ty = format!("?{ty}");
        }
        fields.push(format!("{field}: {ty}"));
    }
    if fields.is_empty() {
        bail!("type {name} has no properties; not representable in varlink");
    }
    Ok(format!("type {name} ({})\n", fields.join(", ")))
}

fn convert(v: &Value) -> Result<String> {
    if let Some(reference) = v.get("$ref").and_then(Value::as_str) {
        return Ok(ref_name(reference).to_string());
    }
    if let Some(variants) = v.get("enum").and_then(Value::as_array) {
        let list: Vec<String> = variants
            .iter()
            .map(|x| x.as_str().unwrap_or_default().to_string())
            .collect();
        return Ok(format!("({})", list.join(", ")));
    }
    // schemars represents Option<T> as a nullable type union, e.g.
    // {"type": ["string", "null"]} -> varlink `?string`.
    if let Some(types) = v.get("type").and_then(Value::as_array) {
        let non_null: Vec<&str> = types
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| *t != "null")
            .collect();
        if non_null.len() == 1 {
            let prefix = if types.len() == 2 { "?" } else { "" };
            return Ok(format!("{prefix}{}", scalar_type(non_null[0])?));
        }
        bail!("type union outside the convertible subset: {types:?}");
    }
    if let Some(any) = v.get("anyOf").and_then(Value::as_array) {
        let nulls = any
            .iter()
            .filter(|x| x.get("type") == Some(&Value::String("null".into())))
            .count();
        if nulls == 1 && any.len() == 2 {
            let other = any
                .iter()
                .find(|x| x.get("type") != Some(&Value::String("null".into())))
                .expect("two-member union with one null has another member");
            return Ok(format!("?{}", convert(other)?));
        }
        bail!("union outside the convertible subset: {any:?}");
    }
    match v.get("type").and_then(Value::as_str) {
        Some("string") => Ok("string".into()),
        Some("integer") => Ok("int".into()),
        Some("number") => Ok("float".into()),
        Some("boolean") => Ok("bool".into()),
        Some("array") => {
            let items = v.get("items").unwrap_or(&Value::Null);
            Ok(format!("[]{}", convert(items)?))
        }
        Some("object") => {
            if let Some(extra) = v.get("additionalProperties").filter(|e| !e.is_boolean()) {
                return Ok(format!("[string]{}", convert(extra)?));
            }
            if v.get("properties")
                .is_some_and(|p| !p.as_object().is_none_or(|m| m.is_empty()))
            {
                bail!("inline object with properties is not representable in varlink: {v:?}");
            }
            Ok("object".into())
        }
        None => Ok("object".into()), // free-form schema (true / empty)
        Some(other) => bail!("unsupported JSON Schema type `{other}`"),
    }
}

fn scalar_type(name: &str) -> Result<&'static str> {
    match name {
        "string" => Ok("string"),
        "integer" => Ok("int"),
        "number" => Ok("float"),
        "boolean" => Ok("bool"),
        other => bail!("unsupported scalar type `{other}` in nullable union"),
    }
}

fn ref_name(reference: &str) -> &str {
    reference.rsplit('/').next().unwrap_or(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_interfaces_render() {
        let interfaces = interfaces().expect("interfaces render");
        assert_eq!(interfaces.len(), 3);
        for (file, body) in &interfaces {
            assert!(file.ends_with(".varlink"), "{file}");
            assert!(body.starts_with("interface com.ibexwall."), "{file}");
        }
    }

    #[test]
    fn core_idl_declares_every_referenced_type() {
        let (_, core) = &interfaces().unwrap()[0];
        for ty in CORE_TYPES {
            assert!(
                core.contains(&format!("type {ty} (")),
                "missing declaration for {ty}"
            );
        }
    }

    #[test]
    fn scalar_conversions() {
        assert_eq!(
            convert(&serde_json::json!({"type": "string"})).unwrap(),
            "string"
        );
        assert_eq!(
            convert(&serde_json::json!({"type": "integer"})).unwrap(),
            "int"
        );
        assert_eq!(
            convert(&serde_json::json!({"type": "array", "items": {"type": "string"}})).unwrap(),
            "[]string"
        );
        assert_eq!(
            convert(
                &serde_json::json!({"type": "object", "additionalProperties": {"type": "string"}})
            )
            .unwrap(),
            "[string]string"
        );
        assert_eq!(
            convert(&serde_json::json!({"anyOf": [{"type": "string"}, {"type": "null"}]})).unwrap(),
            "?string"
        );
    }
}
