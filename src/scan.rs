//! Collect candidate files, run detectors, attach risks.

use crate::detect::{self, Confidence};
use crate::registry::{self, Kind, Registry};
use crate::risk::{self, Risk, Severity};
use crate::secret::Secret;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Directories never worth descending into when looking for project `.env` files.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    "Pods",
    ".cache",
    "DerivedData",
    ".gradle",
    ".terraform",
    "Library",
    ".Trash",
    ".npm",
    ".cargo",
    ".rustup",
    "site-packages",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Folders under $HOME searched for project files when no `--path` is given.
pub const DEFAULT_PROJECT_DIRS: &[&str] = &[
    "Documents/GitHub",
    "Developer",
    "code",
    "Code",
    "src",
    "dev",
    "projects",
    "Projects",
    "repos",
    "workspace",
    "git",
    "work",
];

pub struct ScanOptions {
    pub home: PathBuf,
    /// Project roots to walk for `.env` and project-level MCP configs.
    pub roots: Vec<PathBuf>,
    pub registry: Registry,
    pub check_git: bool,
    pub max_depth: usize,
}

impl ScanOptions {
    pub fn default_roots(home: &Path) -> Vec<PathBuf> {
        DEFAULT_PROJECT_DIRS.iter().map(|d| home.join(d)).filter(|p| p.is_dir()).collect()
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub tool: String,
    pub kind: Kind,
    pub path: PathBuf,
    pub line: usize,
    pub provider: &'static str,
    pub provider_name: &'static str,
    pub var_name: Option<String>,
    pub fingerprint: String,
    pub confidence: Confidence,
    pub risks: Vec<Risk>,
    pub severity: Severity,
    /// Days since the file was last modified (a proxy for key age).
    pub age_days: Option<u64>,
    #[serde(skip_serializing)]
    pub secret: Secret,
    #[serde(skip_serializing)]
    pub env_ref: Option<String>,
}

impl Finding {
    /// Environment variable name to use when moving this key out of the file.
    pub fn env_name(&self) -> String {
        match &self.var_name {
            Some(n) if n.len() > 3 && n.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') => n.clone(),
            _ => detect::provider(self.provider).env_var.to_string(),
        }
    }
}

struct Target {
    path: PathBuf,
    tool: String,
    kind: Kind,
    provider: Option<&'static str>,
    env_ref: Option<String>,
}

fn project_target(path: &Path) -> Option<Target> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("");
    // Name of the enclosing repo, else the nearest non-hidden parent folder.
    let project = |p: &Path| {
        p.ancestors()
            .skip(1)
            .find(|a| a.join(".git").exists())
            .or_else(|| {
                p.ancestors()
                    .skip(1)
                    .find(|a| a.file_name().is_some_and(|n| !n.to_string_lossy().starts_with('.')))
            })
            .and_then(|a| a.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    let (tool, kind, env_ref) = if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") || name == ".envrc" {
        (format!("dotenv ({})", project(path)), Kind::Dotenv, None)
    } else if name == ".mcp.json" {
        // Claude Code expands ${VAR} in .mcp.json.
        (
            format!("Claude Code MCP project ({})", project(path)),
            Kind::Config,
            Some("${%s}".to_string()),
        )
    } else if parent == ".claude" && name.starts_with("settings") {
        (format!("Claude Code project ({})", project(path)), Kind::Config, None)
    } else if parent == ".cursor" && name == "mcp.json" {
        (
            format!("Cursor MCP project ({})", project(path)),
            Kind::Config,
            Some("${env:%s}".to_string()),
        )
    } else if parent == ".vscode" && name == "mcp.json" {
        (format!("VS Code MCP project ({})", project(path)), Kind::Config, None)
    } else {
        return None;
    };
    Some(Target {
        path: path.to_path_buf(),
        tool,
        kind,
        provider: None,
        env_ref,
    })
}

fn collect_targets(opts: &ScanOptions) -> Vec<Target> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    let mut push = |t: Target, targets: &mut Vec<Target>| {
        let key = t.path.canonicalize().unwrap_or_else(|_| t.path.clone());
        if seen.insert(key) {
            targets.push(t);
        }
    };

    for tool in &opts.registry.tools {
        let provider = tool.provider.as_deref().map(|p| detect::provider(p).id);
        for pattern in &tool.paths {
            for path in registry::resolve(pattern, &opts.home) {
                let t = Target {
                    path,
                    tool: tool.name.clone(),
                    kind: tool.kind,
                    provider,
                    env_ref: tool.env_ref.clone(),
                };
                push(t, &mut targets);
            }
        }
    }

    for root in &opts.roots {
        let walker = WalkDir::new(root)
            .max_depth(opts.max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !e.file_type().is_dir() || !SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()));
        for entry in walker.flatten() {
            if entry.file_type().is_file()
                && let Some(t) = project_target(entry.path())
            {
                push(t, &mut targets);
            }
        }
    }
    targets
}

fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path).ok()?.read_to_end(&mut buf).ok()?;
    if buf.iter().take(8192).any(|&b| b == 0) {
        return None;
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    zeroize::Zeroize::zeroize(&mut buf);
    Some(text)
}

fn age_days(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(SystemTime::now().duration_since(modified).ok()?.as_secs() / 86_400)
}

fn finding_id(path: &Path, line: usize, fingerprint: &str) -> String {
    let digest = Sha256::digest(format!("{}:{line}:{fingerprint}", path.display()).as_bytes());
    digest.iter().take(3).map(|b| format!("{b:02x}")).collect()
}

fn is_exported(kind: Kind, line: &str) -> bool {
    let t = line.trim_start();
    match kind {
        Kind::Shell => !t.starts_with('#'),
        Kind::Dotenv => t.starts_with("export "),
        Kind::Config => false,
    }
}

pub fn scan(opts: &ScanOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    for target in collect_targets(opts) {
        let Some(mut text) = read_text(&target.path) else { continue };
        let mut file_findings = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if matches!(target.kind, Kind::Shell | Kind::Dotenv) && trimmed.starts_with('#') {
                continue;
            }
            for d in detect::scan_line(line, target.provider) {
                let provider = detect::provider(d.provider);
                let fingerprint = d.secret.fingerprint(&d.prefix);
                let mut risks = vec![Risk::Plaintext];
                if is_exported(target.kind, line) {
                    risks.push(Risk::ShellExported);
                }
                file_findings.push(Finding {
                    id: finding_id(&target.path, idx + 1, &fingerprint),
                    tool: target.tool.clone(),
                    kind: target.kind,
                    path: target.path.clone(),
                    line: idx + 1,
                    provider: provider.id,
                    provider_name: provider.name,
                    var_name: d.var_name,
                    fingerprint,
                    confidence: d.confidence,
                    risks,
                    severity: Severity::Low,
                    age_days: None,
                    secret: d.secret,
                    env_ref: target.env_ref.clone(),
                });
            }
        }
        zeroize::Zeroize::zeroize(&mut text);
        if file_findings.is_empty() {
            continue;
        }

        let shared: Vec<Risk> = [risk::permission_risk(&target.path), risk::cloud_sync_risk(&target.path, &opts.home)]
            .into_iter()
            .flatten()
            .collect();
        let git = if opts.check_git {
            let secrets: Vec<&Secret> = file_findings.iter().map(|f| &f.secret).collect();
            risk::git_risks(&target.path, &secrets)
        } else {
            vec![Vec::new(); file_findings.len()]
        };
        let age = age_days(&target.path);
        for (mut f, git_risks) in file_findings.into_iter().zip(git) {
            f.risks.extend(shared.iter().cloned());
            f.risks.extend(git_risks);
            f.severity = f.risks.iter().map(Risk::severity).max().unwrap_or(Severity::Low);
            f.age_days = age;
            findings.push(f);
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then(a.line.cmp(&b.line))
    });
    findings
}
