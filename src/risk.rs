//! Risk checks for a file holding a credential: permissions, cloud sync, git.

use crate::secret::Secret;
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Risk {
    /// Stored as a literal value in a plain file.
    Plaintext,
    GroupReadable {
        mode: String,
    },
    WorldReadable {
        mode: String,
    },
    /// File lives in a folder that syncs to a cloud provider.
    CloudSynced {
        service: String,
    },
    /// File is tracked by git right now (`committed`: the key is in a commit).
    TrackedInGit {
        repo: PathBuf,
        committed: bool,
    },
    /// File is no longer tracked, but this exact key is still in the repo's history.
    InGitHistory {
        repo: PathBuf,
    },
    /// Set in a shell startup file, so every process you start inherits it.
    ShellExported,
}

impl Risk {
    pub fn label(&self) -> String {
        match self {
            Risk::Plaintext => "plaintext".into(),
            Risk::GroupReadable { mode } => format!("group-readable ({mode})"),
            Risk::WorldReadable { mode } => format!("world-readable ({mode})"),
            Risk::CloudSynced { service } => format!("synced: {service}"),
            Risk::TrackedInGit { committed: true, .. } => "committed to git".into(),
            Risk::TrackedInGit { committed: false, .. } => "tracked by git (not committed yet)".into(),
            Risk::InGitHistory { .. } => "in git history".into(),
            Risk::ShellExported => "exported to all processes".into(),
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Risk::TrackedInGit { .. } | Risk::InGitHistory { .. } | Risk::CloudSynced { .. } => Severity::Critical,
            Risk::WorldReadable { .. } | Risk::ShellExported => Severity::High,
            Risk::GroupReadable { .. } => Severity::Medium,
            Risk::Plaintext => Severity::Low,
        }
    }

    pub fn rule_id(&self) -> &'static str {
        match self {
            Risk::Plaintext => "plaintext",
            Risk::GroupReadable { .. } => "group-readable",
            Risk::WorldReadable { .. } => "world-readable",
            Risk::CloudSynced { .. } => "cloud-synced",
            Risk::TrackedInGit { .. } => "tracked-in-git",
            Risk::InGitHistory { .. } => "in-git-history",
            Risk::ShellExported => "shell-exported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[cfg(unix)]
pub fn permission_risk(path: &Path) -> Option<Risk> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    let text = format!("{mode:04o}");
    if mode & 0o004 != 0 {
        Some(Risk::WorldReadable { mode: text })
    } else if mode & 0o040 != 0 {
        Some(Risk::GroupReadable { mode: text })
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn permission_risk(_path: &Path) -> Option<Risk> {
    None
}

/// Detect whether `path` sits inside a folder synced by iCloud, Dropbox,
/// Google Drive, OneDrive or Box.
pub fn cloud_sync_risk(path: &Path, home: &Path) -> Option<Risk> {
    let real = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let home_real = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let mut roots: Vec<(PathBuf, String)> = vec![
        (home_real.join("Library/Mobile Documents"), "iCloud Drive".into()),
        (home_real.join("Dropbox"), "Dropbox".into()),
        (home_real.join("Google Drive"), "Google Drive".into()),
        (home_real.join("OneDrive"), "OneDrive".into()),
        (home_real.join("Box"), "Box".into()),
    ];
    if let Ok(entries) = std::fs::read_dir(home_real.join("Library/CloudStorage")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let service = name.split('-').next().unwrap_or(&name).to_string();
            roots.push((e.path(), service));
        }
    }
    // iCloud "Desktop & Documents Folders" syncs ~/Desktop and ~/Documents in place.
    let icloud_docs = home_real.join("Library/Mobile Documents/com~apple~CloudDocs/Documents");
    if icloud_docs.is_dir() {
        roots.push((home_real.join("Documents"), "iCloud Desktop & Documents".into()));
        roots.push((home_real.join("Desktop"), "iCloud Desktop & Documents".into()));
    }
    roots
        .into_iter()
        .find(|(root, _)| real.starts_with(root))
        .map(|(_, service)| Risk::CloudSynced { service })
}

/// Walk up from `path` to the enclosing git work tree.
pub fn find_repo(path: &Path) -> Option<PathBuf> {
    let mut dir = path.parent()?;
    loop {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

fn git(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .arg("--no-pager")
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0");
    cmd.stdin(Stdio::null()).stderr(Stdio::null());
    cmd
}

/// Git risks for each secret found in `path`. Secrets are matched in-process
/// against `git log -p` output, so they never appear on a command line.
pub fn git_risks(path: &Path, secrets: &[&Secret]) -> Vec<Vec<Risk>> {
    let mut out = vec![Vec::new(); secrets.len()];
    let Some(repo) = find_repo(path) else { return out };
    let Ok(rel) = path.strip_prefix(&repo) else { return out };
    let spec = format!(":(literal){}", rel.to_string_lossy());

    let tracked = git(&repo)
        .args(["ls-files", "--error-unmatch", "--", &spec])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let Ok(mut child) = git(&repo)
        .args(["log", "--all", "-p", "--no-color", "--no-ext-diff", "--format=", "--", &spec])
        .stdout(Stdio::piped())
        .spawn()
    else {
        return out;
    };
    let mut seen = vec![false; secrets.len()];
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).split(b'\n').map_while(Result::ok) {
            let line = String::from_utf8_lossy(&line);
            for (i, s) in secrets.iter().enumerate() {
                if !seen[i] && line.contains(s.expose()) {
                    seen[i] = true;
                }
            }
            if seen.iter().all(|&x| x) {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    for (i, committed) in seen.into_iter().enumerate() {
        if tracked {
            out[i].push(Risk::TrackedInGit {
                repo: repo.clone(),
                committed,
            });
        } else if committed {
            out[i].push(Risk::InGitHistory { repo: repo.clone() });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Medium > Severity::Low);
    }

    #[cfg(unix)]
    #[test]
    fn permission_checks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, "x").unwrap();
        for (mode, want) in [(0o600, None), (0o640, Some("group")), (0o644, Some("world"))] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            let got = permission_risk(&f).map(|r| r.rule_id());
            match want {
                None => assert_eq!(got, None),
                Some(w) => assert!(got.unwrap().starts_with(w)),
            }
        }
    }

    #[test]
    fn cloud_sync_detection() {
        let home = tempfile::tempdir().unwrap();
        let synced = home.path().join("Library/CloudStorage/Dropbox-Personal/proj");
        std::fs::create_dir_all(&synced).unwrap();
        std::fs::write(synced.join(".env"), "x").unwrap();
        let r = cloud_sync_risk(&synced.join(".env"), home.path());
        assert_eq!(r, Some(Risk::CloudSynced { service: "Dropbox".into() }));

        std::fs::create_dir_all(home.path().join("code")).unwrap();
        std::fs::write(home.path().join("code/.env"), "x").unwrap();
        assert_eq!(cloud_sync_risk(&home.path().join("code/.env"), home.path()), None);
    }
}
