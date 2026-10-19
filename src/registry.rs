//! The location registry: which files each AI tool uses for credentials.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const BUILTIN: &str = include_str!("registry.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Config,
    Shell,
    /// `.env`-style file found while walking project directories.
    Dotenv,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub kind: Kind,
    pub provider: Option<String>,
    pub env_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Registry {
    #[serde(rename = "tool")]
    pub tools: Vec<Tool>,
}

impl Registry {
    pub fn builtin() -> Self {
        toml::from_str(BUILTIN).expect("built-in registry parses")
    }

    /// Built-in registry plus any tools from a user file (appended).
    pub fn load(extra: Option<&Path>) -> Result<Self> {
        let mut reg = Self::builtin();
        if let Some(path) = extra {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let more: Registry = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
            reg.tools.extend(more.tools);
        }
        Ok(reg)
    }
}

pub fn expand_home(pattern: &str, home: &Path) -> PathBuf {
    match pattern.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if pattern == "~" => home.to_path_buf(),
        None => PathBuf::from(pattern),
    }
}

/// Resolve a registry path (with `~` and globs) to existing files.
pub fn resolve(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let expanded = expand_home(pattern, home);
    let s = expanded.to_string_lossy();
    if s.contains(['*', '?', '[']) {
        // Escape glob metacharacters in the home part so odd home paths still work.
        let escaped = format!(
            "{}{}",
            glob::Pattern::escape(&home.to_string_lossy()),
            &s[home.to_string_lossy().len()..]
        );
        let pat = if s.starts_with(&*home.to_string_lossy()) {
            escaped
        } else {
            s.to_string()
        };
        glob::glob(&pat)
            .map(|paths| paths.flatten().filter(|p| p.is_file()).collect())
            .unwrap_or_default()
    } else if expanded.is_file() {
        vec![expanded]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_parses_and_has_core_tools() {
        let reg = Registry::builtin();
        for name in [
            "Claude Code",
            "OpenCode",
            "OpenCode auth store",
            "Codex CLI",
            "Cursor MCP",
            "Shell profile",
        ] {
            assert!(reg.tools.iter().any(|t| t.name == name), "missing {name}");
        }
        for t in &reg.tools {
            if let Some(p) = &t.provider {
                assert_ne!(crate::detect::provider(p).id, "unknown", "bad provider id {p} in {}", t.name);
            }
            if let Some(r) = &t.env_ref {
                assert!(r.contains("%s"), "env_ref without %s in {}", t.name);
            }
        }
    }

    #[test]
    fn resolves_globs_under_home() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/fish/conf.d")).unwrap();
        std::fs::write(dir.path().join(".config/fish/conf.d/keys.fish"), "x").unwrap();
        std::fs::write(dir.path().join(".zshrc"), "x").unwrap();
        assert_eq!(resolve("~/.config/fish/conf.d/*.fish", dir.path()).len(), 1);
        assert_eq!(resolve("~/.zshrc", dir.path()).len(), 1);
        assert!(resolve("~/.bashrc", dir.path()).is_empty());
    }
}
