//! Fix actions: tighten permissions, move keys into the macOS Keychain and
//! rewrite the source file to reference the key instead of containing it.

use crate::registry::Kind;
use crate::risk::Risk;
use crate::scan::Finding;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const SERVICE: &str = "keysweep";

/// Where moved keys live. The real implementation is the macOS Keychain; tests
/// use an in-memory store.
pub trait SecretStore {
    fn get(&self, account: &str) -> Result<Option<zeroize::Zeroizing<String>>>;
    fn set(&self, account: &str, secret: &str) -> Result<()>;
    /// Shell expression that prints the stored secret.
    fn lookup_command(&self, account: &str) -> String {
        format!("security find-generic-password -s {SERVICE} -a {account} -w")
    }
}

pub struct Keychain;

impl SecretStore for Keychain {
    fn get(&self, account: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
        ensure_macos()?;
        match keyring::Entry::new(SERVICE, account)?.get_password() {
            Ok(p) => Ok(Some(zeroize::Zeroizing::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, account: &str, secret: &str) -> Result<()> {
        ensure_macos()?;
        keyring::Entry::new(SERVICE, account)?.set_password(secret)?;
        // Verify through the same CLI the rewritten config will use. The secret
        // comes back over a pipe, never via argv.
        let out = std::process::Command::new("security")
            .args(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
            .output()
            .context("running `security`")?;
        let mut stdout = out.stdout;
        let ok = out.status.success() && stdout.strip_suffix(b"\n").unwrap_or(&stdout) == secret.as_bytes();
        zeroize::Zeroize::zeroize(&mut stdout);
        if !ok {
            bail!("keychain read-back did not match for account {account}; file left unchanged");
        }
        Ok(())
    }
}

fn ensure_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        bail!("keychain migration currently supports macOS only (use --perms, or move keys manually)")
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore(pub std::cell::RefCell<HashMap<String, String>>);

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, account: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
        Ok(self.0.borrow().get(account).cloned().map(zeroize::Zeroizing::new))
    }
    fn set(&self, account: &str, secret: &str) -> Result<()> {
        self.0.borrow_mut().insert(account.into(), secret.into());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewrite {
    /// Replace the value with `"$(security find-generic-password ...)"`.
    ShellLookup,
    /// Comment the line out (dotenv files can't run commands).
    CommentOut,
    /// Replace the literal with the tool's env-var reference syntax.
    EnvRef(String),
    /// Format not safe to rewrite automatically.
    Manual(String),
}

#[derive(Debug)]
pub enum Action<'a> {
    Chmod {
        path: PathBuf,
        mode: String,
    },
    Move {
        finding: &'a Finding,
        env: String,
        rewrite: Rewrite,
    },
}

pub fn rewrite_for(f: &Finding) -> Rewrite {
    let name = f.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    match f.kind {
        Kind::Shell => Rewrite::ShellLookup,
        Kind::Dotenv if name == ".envrc" => Rewrite::ShellLookup,
        Kind::Dotenv => Rewrite::CommentOut,
        Kind::Config => match &f.env_ref {
            Some(t) => Rewrite::EnvRef(t.replace("%s", &f.env_name())),
            None => Rewrite::Manual(format!(
                "{} does not support env-var references here; remove the key from this file (or log out/in with the tool) and it will read ${} from the environment",
                f.tool,
                f.env_name()
            )),
        },
    }
}

pub fn plan<'a>(findings: &'a [&'a Finding], perms: bool, keychain: bool) -> Vec<Action<'a>> {
    let mut actions = Vec::new();
    let mut chmodded = HashSet::new();
    for f in findings {
        if perms {
            for r in &f.risks {
                if let Risk::GroupReadable { mode } | Risk::WorldReadable { mode } = r
                    && chmodded.insert(f.path.clone())
                {
                    actions.push(Action::Chmod {
                        path: f.path.clone(),
                        mode: mode.clone(),
                    });
                }
            }
        }
        if keychain {
            actions.push(Action::Move {
                finding: f,
                env: f.env_name(),
                rewrite: rewrite_for(f),
            });
        }
    }
    actions
}

/// Pick a keychain account: the env name, unless that already holds a different key.
fn choose_account(store: &dyn SecretStore, env: &str, f: &Finding) -> Result<String> {
    match store.get(env)? {
        Some(existing) if existing.as_str() != f.secret.expose() => Ok(format!("{env}_{}", f.secret.short_hash())),
        _ => Ok(env.to_string()),
    }
}

/// Compute the new line for `rewrite`, or None if the secret is no longer on that line.
pub fn rewrite_line(line: &str, secret: &str, rewrite: &Rewrite, lookup: &str, env: &str, account: &str) -> Option<String> {
    let start = line.find(secret)?;
    let end = start + secret.len();
    match rewrite {
        Rewrite::ShellLookup => {
            let b = line.as_bytes();
            let (s, e) = match (start.checked_sub(1).map(|i| b[i]), b.get(end)) {
                (Some(q @ (b'"' | b'\'')), Some(q2)) if q == *q2 => (start - 1, end + 1),
                _ => (start, end),
            };
            Some(format!("{}\"$({lookup})\"{}", &line[..s], &line[e..]))
        }
        Rewrite::CommentOut => {
            let indent = &line[..line.len() - line.trim_start().len()];
            Some(format!(
                "{indent}# {env} moved to macOS Keychain by keysweep (account {account}); load it with: eval \"$(keysweep env)\""
            ))
        }
        Rewrite::EnvRef(r) => Some(format!("{}{r}{}", &line[..start], &line[end..])),
        Rewrite::Manual(_) => None,
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// env var name -> keychain account. Contains no secret material.
    pub entries: BTreeMap<String, ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub account: String,
    pub fingerprint: String,
    pub source: PathBuf,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(serde_json::from_str(&t).with_context(|| format!("parsing {}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    /// Shell lines that export each stored key, for `eval "$(keysweep env)"`.
    pub fn exports(&self, store: &dyn SecretStore) -> String {
        self.entries
            .iter()
            .map(|(env, e)| format!("export {env}=\"$({} 2>/dev/null)\"\n", store.lookup_command(&e.account)))
            .collect()
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn current_mode(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o600)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0o600
    }
}

fn mkdir_private(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    set_mode(dir, 0o700)
}

/// Write `data` to `path` with 0600 permissions, atomically.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        mkdir_private(parent)?;
    }
    atomic_write(path, data, 0o600)
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent dir for {}", path.display()))?;
    let tmp = dir.join(format!(".{}.keysweep-tmp", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&tmp, data)?;
    set_mode(&tmp, mode)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub struct Applier<'s> {
    pub store: &'s dyn SecretStore,
    pub backup_dir: PathBuf,
    pub manifest_path: PathBuf,
    backed_up: HashMap<PathBuf, PathBuf>,
}

#[derive(Debug)]
pub struct Outcome {
    pub message: String,
    pub backup: Option<PathBuf>,
}

impl<'s> Applier<'s> {
    pub fn new(store: &'s dyn SecretStore, state_dir: &Path, run_id: &str) -> Self {
        Applier {
            store,
            backup_dir: state_dir.join("backups").join(run_id),
            manifest_path: state_dir.join("manifest.json"),
            backed_up: HashMap::new(),
        }
    }

    fn backup(&mut self, path: &Path) -> Result<PathBuf> {
        if let Some(b) = self.backed_up.get(path) {
            return Ok(b.clone());
        }
        let name = path.to_string_lossy().trim_start_matches('/').replace('/', "%");
        let dest = self.backup_dir.join(name);
        mkdir_private(&self.backup_dir)?;
        std::fs::copy(path, &dest).with_context(|| format!("backing up {}", path.display()))?;
        set_mode(&dest, 0o600)?;
        self.backed_up.insert(path.to_path_buf(), dest.clone());
        Ok(dest)
    }

    pub fn apply(&mut self, action: &Action) -> Result<Outcome> {
        match action {
            Action::Chmod { path, mode } => {
                set_mode(path, 0o600)?;
                Ok(Outcome {
                    message: format!("chmod {mode} -> 0600"),
                    backup: None,
                })
            }
            Action::Move { finding: f, env, rewrite } => {
                // Check the file before touching the keychain, so a stale scan changes nothing.
                let text = std::fs::read_to_string(&f.path)?;
                let line = text
                    .lines()
                    .nth(f.line - 1)
                    .ok_or_else(|| anyhow!("line {} no longer exists", f.line))?;
                if !line.contains(f.secret.expose()) {
                    bail!("key is no longer on line {}; re-run `keysweep scan`", f.line);
                }

                let account = choose_account(self.store, env, f)?;
                self.store.set(&account, f.secret.expose())?;
                let mut manifest = Manifest::load(&self.manifest_path)?;
                manifest.entries.insert(
                    env.clone(),
                    ManifestEntry {
                        account: account.clone(),
                        fingerprint: f.fingerprint.clone(),
                        source: f.path.clone(),
                    },
                );
                manifest.save(&self.manifest_path)?;

                let lookup = self.store.lookup_command(&account);
                let Some(new_line) = rewrite_line(line, f.secret.expose(), rewrite, &lookup, env, &account) else {
                    let why = match rewrite {
                        Rewrite::Manual(why) => why.clone(),
                        _ => "could not rewrite line".into(),
                    };
                    return Ok(Outcome {
                        message: format!("stored in Keychain as {account}; file NOT changed: {why}"),
                        backup: None,
                    });
                };

                let backup = self.backup(&f.path)?;
                let mut out: Vec<String> = text.lines().map(str::to_string).collect();
                out[f.line - 1] = new_line;
                let mut joined = out.join("\n");
                if text.ends_with('\n') {
                    joined.push('\n');
                }
                atomic_write(&f.path, joined.as_bytes(), current_mode(&f.path))?;
                Ok(Outcome {
                    message: format!("stored in Keychain as {account}; line {} rewritten", f.line),
                    backup: Some(backup),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOKUP: &str = "security find-generic-password -s keysweep -a K -w";

    #[test]
    fn shell_rewrite_strips_quotes() {
        let got = rewrite_line(r#"export K="abc123""#, "abc123", &Rewrite::ShellLookup, LOOKUP, "K", "K").unwrap();
        assert_eq!(got, format!(r#"export K="$({LOOKUP})""#));
        let got = rewrite_line("export K=abc123 # note", "abc123", &Rewrite::ShellLookup, LOOKUP, "K", "K").unwrap();
        assert_eq!(got, format!(r#"export K="$({LOOKUP})" # note"#));
    }

    #[test]
    fn env_ref_rewrite_keeps_json_quotes() {
        let got = rewrite_line(
            r#"  "apiKey": "abc123","#,
            "abc123",
            &Rewrite::EnvRef("${env:K}".into()),
            LOOKUP,
            "K",
            "K",
        )
        .unwrap();
        assert_eq!(got, r#"  "apiKey": "${env:K}","#);
    }

    #[test]
    fn comment_out_drops_secret() {
        let got = rewrite_line("  K=abc123", "abc123", &Rewrite::CommentOut, LOOKUP, "K", "K").unwrap();
        assert!(got.starts_with("  # K moved"));
        assert!(!got.contains("abc123"));
    }

    #[test]
    fn manual_and_missing_return_none() {
        assert!(rewrite_line("x", "abc", &Rewrite::ShellLookup, LOOKUP, "K", "K").is_none());
        assert!(rewrite_line("abc", "abc", &Rewrite::Manual("n/a".into()), LOOKUP, "K", "K").is_none());
    }

    #[test]
    fn manifest_exports() {
        let mut m = Manifest::default();
        m.entries.insert(
            "OPENAI_API_KEY".into(),
            ManifestEntry {
                account: "OPENAI_API_KEY".into(),
                fingerprint: "sk-proj-…12345678".into(),
                source: "/x".into(),
            },
        );
        let out = m.exports(&MemoryStore::default());
        assert_eq!(
            out,
            "export OPENAI_API_KEY=\"$(security find-generic-password -s keysweep -a OPENAI_API_KEY -w 2>/dev/null)\"\n"
        );
    }

    #[test]
    fn applier_moves_shell_key_and_records_manifest() {
        use crate::detect::testkeys;
        use crate::registry::Registry;
        use crate::scan::{ScanOptions, scan};

        let home = tempfile::tempdir().unwrap();
        let key = testkeys::anthropic(42);
        let zshrc = home.path().join(".zshrc");
        std::fs::write(&zshrc, format!("alias ll='ls -l'\nexport ANTHROPIC_API_KEY=\"{key}\"\n")).unwrap();

        let opts = ScanOptions {
            home: home.path().into(),
            roots: vec![],
            registry: Registry::builtin(),
            check_git: false,
            max_depth: 3,
        };
        let findings = scan(&opts);
        assert_eq!(findings.len(), 1);
        let selected: Vec<&Finding> = findings.iter().collect();
        let actions = plan(&selected, false, true);
        assert!(matches!(
            &actions[0],
            Action::Move {
                rewrite: Rewrite::ShellLookup,
                ..
            }
        ));

        let store = MemoryStore::default();
        let state = home.path().join(".keysweep");
        let mut applier = Applier::new(&store, &state, "run1");
        let outcome = applier.apply(&actions[0]).unwrap();

        let text = std::fs::read_to_string(&zshrc).unwrap();
        assert!(!text.contains(&key));
        assert_eq!(
            text,
            "alias ll='ls -l'\nexport ANTHROPIC_API_KEY=\"$(security find-generic-password -s keysweep -a ANTHROPIC_API_KEY -w)\"\n"
        );
        assert_eq!(store.0.borrow().get("ANTHROPIC_API_KEY").unwrap(), &key);
        let backup = outcome.backup.unwrap();
        assert!(std::fs::read_to_string(backup).unwrap().contains(&key));

        let manifest = Manifest::load(&state.join("manifest.json")).unwrap();
        assert_eq!(manifest.entries["ANTHROPIC_API_KEY"].account, "ANTHROPIC_API_KEY");
        assert!(!std::fs::read_to_string(state.join("manifest.json")).unwrap().contains(&key));

        // A second scan finds nothing: the file now references the keychain.
        assert!(scan(&opts).is_empty());
    }

    #[test]
    fn account_collision_gets_suffix() {
        use crate::detect::testkeys;
        let home = tempfile::tempdir().unwrap();
        let (k1, k2) = (testkeys::openai(1), testkeys::openai(2));
        std::fs::write(
            home.path().join(".zshrc"),
            format!("export OPENAI_API_KEY={k1}\nexport OPENAI_API_KEY={k2}\n"),
        )
        .unwrap();
        let opts = crate::scan::ScanOptions {
            home: home.path().into(),
            roots: vec![],
            registry: crate::registry::Registry::builtin(),
            check_git: false,
            max_depth: 3,
        };
        let findings = crate::scan::scan(&opts);
        let selected: Vec<&Finding> = findings.iter().collect();
        let store = MemoryStore::default();
        let mut applier = Applier::new(&store, &home.path().join(".keysweep"), "r");
        for a in plan(&selected, false, true) {
            applier.apply(&a).unwrap();
        }
        let accounts: Vec<String> = store.0.borrow().keys().cloned().collect();
        assert_eq!(accounts.len(), 2, "{accounts:?}");
        assert!(accounts.contains(&"OPENAI_API_KEY".to_string()));
    }

    #[test]
    fn stale_finding_changes_nothing() {
        use crate::detect::testkeys;
        let home = tempfile::tempdir().unwrap();
        let rc = home.path().join(".zshrc");
        std::fs::write(&rc, format!("export GROQ_API_KEY={}\n", testkeys::groq(3))).unwrap();
        let opts = crate::scan::ScanOptions {
            home: home.path().into(),
            roots: vec![],
            registry: crate::registry::Registry::builtin(),
            check_git: false,
            max_depth: 3,
        };
        let findings = crate::scan::scan(&opts);
        std::fs::write(&rc, "export GROQ_API_KEY=rotated\n").unwrap();
        let selected: Vec<&Finding> = findings.iter().collect();
        let store = MemoryStore::default();
        let mut applier = Applier::new(&store, &home.path().join(".keysweep"), "r");
        assert!(applier.apply(&plan(&selected, false, true)[0]).is_err());
        assert!(store.0.borrow().is_empty());
    }
}
