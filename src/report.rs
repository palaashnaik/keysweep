//! Table, JSON and SARIF output. None of these ever touch `Finding::secret`.

use crate::detect;
use crate::risk::Severity;
use crate::scan::Finding;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

pub fn tilde(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn sev_color(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::Red,
        Severity::High => Color::Magenta,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Grey,
    }
}

fn age(f: &Finding) -> String {
    match f.age_days {
        Some(0) => "today".into(),
        Some(d) if d < 60 => format!("{d}d"),
        Some(d) if d < 730 => format!("{}mo", d / 30),
        Some(d) => format!("{}y", d / 365),
        None => "-".into(),
    }
}

pub fn table(findings: &[Finding], home: &Path, color: bool) -> String {
    let mut t = Table::new();
    t.load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    if !color {
        t.force_no_tty();
    }
    t.set_header(["ID", "SEVERITY", "TOOL", "PROVIDER", "KEY", "FILE", "RISKS", "AGE"]);
    for f in findings {
        let sev = Cell::new(f.severity.as_str()).fg(sev_color(f.severity));
        let sev = if f.severity == Severity::Critical {
            sev.add_attribute(Attribute::Bold)
        } else {
            sev
        };
        let risks: Vec<String> = f
            .risks
            .iter()
            .filter(|r| r.rule_id() != "plaintext" || f.risks.len() == 1)
            .map(|r| r.label())
            .collect();
        let provider = match f.confidence {
            detect::Confidence::High => f.provider_name.to_string(),
            detect::Confidence::Medium => format!("{} (likely)", f.provider_name),
        };
        t.add_row(vec![
            Cell::new(&f.id),
            sev,
            Cell::new(&f.tool),
            Cell::new(provider),
            Cell::new(&f.fingerprint),
            Cell::new(format!("{}:{}", tilde(&f.path, home), f.line)),
            Cell::new(risks.join("\n")),
            Cell::new(age(f)),
        ]);
    }
    t.to_string()
}

pub fn summary(findings: &[Finding]) -> String {
    let files: BTreeSet<_> = findings.iter().map(|f| &f.path).collect();
    let count = |s| findings.iter().filter(|f| f.severity == s).count();
    format!(
        "{} key(s) in {} file(s): {} critical, {} high, {} medium, {} low",
        findings.len(),
        files.len(),
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
    )
}

/// Revoke / spend-limit links for every provider present in `findings`.
pub fn links<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> String {
    let ids: BTreeSet<&str> = findings.into_iter().map(|f| f.provider).filter(|p| *p != "unknown").collect();
    let mut out = String::new();
    for id in ids {
        let p = detect::provider(id);
        out.push_str(&format!("  {:<20} revoke: {}\n", p.name, p.revoke_url));
        if let Some(l) = p.limits_url {
            out.push_str(&format!("  {:<20} limits: {}\n", "", l));
        }
    }
    out
}

pub fn json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(&json!({ "version": env!("CARGO_PKG_VERSION"), "findings": findings })).unwrap()
}

pub fn sarif(findings: &[Finding]) -> String {
    let level = |s: Severity| match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    };
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let risks: Vec<String> = f.risks.iter().map(|r| r.label()).collect();
            json!({
                "ruleId": format!("keysweep/{}", f.provider),
                "level": level(f.severity),
                "message": { "text": format!("{} key {} stored by {}: {}", f.provider_name, f.fingerprint, f.tool, risks.join(", ")) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": format!("file://{}", f.path.display()) },
                    "region": { "startLine": f.line }
                }}],
                "partialFingerprints": { "keysweep/v1": f.fingerprint },
                "properties": { "id": f.id, "severity": f.severity.as_str(), "risks": f.risks }
            })
        })
        .collect();
    let rules: Vec<_> = findings
        .iter()
        .map(|f| f.provider)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            let p = detect::provider(id);
            json!({
                "id": format!("keysweep/{id}"),
                "name": format!("{} credential", p.name),
                "shortDescription": { "text": format!("Plaintext {} credential on disk", p.name) },
                "helpUri": if p.revoke_url.is_empty() { serde_json::Value::Null } else { p.revoke_url.into() },
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "keysweep",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/palaashnaik/keysweep",
                "rules": rules
            }},
            "results": results
        }]
    }))
    .unwrap()
}
