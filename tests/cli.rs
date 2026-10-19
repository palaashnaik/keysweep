//! End-to-end tests against a fake home directory. Keys are generated at
//! runtime; every test asserts that no raw key ever reaches stdout or stderr.

use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn rand_alnum(seed: u64, len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            CHARS[(x % CHARS.len() as u64) as usize] as char
        })
        .collect()
}

struct Fixture {
    home: tempfile::TempDir,
    keys: Vec<String>,
}

fn write(path: &Path, text: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn fixture() -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let anthropic = format!("{}-{}-{}-{}", "sk", "ant", "api03", rand_alnum(1, 93));
    let openai = format!("{}-{}-{}", "sk", "proj", rand_alnum(2, 120));
    let groq = format!("{}_{}", "gsk", rand_alnum(3, 52));
    let mistral = rand_alnum(4, 32);
    let google = ["AI", "za"].concat() + &rand_alnum(5, 35);

    write(
        &h.join(".zshrc"),
        &format!(
            "export PATH=$PATH:/opt/bin\nexport ANTHROPIC_API_KEY=\"{anthropic}\"\n# export OLD={}\n",
            rand_alnum(9, 40)
        ),
        0o644,
    );
    write(
        &h.join(".local/share/opencode/auth.json"),
        &format!(r#"{{"openai":{{"type":"api","key":"{openai}"}}}}"#),
        0o600,
    );

    // Repo whose .env was committed, then untracked: still in history.
    let repo = h.join("code/app");
    write(
        &repo.join(".env"),
        &format!("GROQ_API_KEY={groq}\nMISTRAL_API_KEY={mistral}\n"),
        0o600,
    );
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", ".env"]);
    git(&repo, &["commit", "-q", "-m", "oops"]);
    git(&repo, &["rm", "-q", "--cached", ".env"]);
    git(&repo, &["commit", "-q", "-m", "untrack"]);

    // Cloud-synced project with a Cursor MCP config.
    write(
        &h.join("Library/CloudStorage/Dropbox-Personal/side/.cursor/mcp.json"),
        &format!("{{\n  \"mcpServers\": {{\n    \"gemini\": {{ \"env\": {{ \"GEMINI_API_KEY\": \"{google}\" }} }}\n  }}\n}}\n"),
        0o644,
    );
    // Noise that must not be reported.
    write(
        &repo.join(".env.example"),
        "OPENAI_API_KEY=your-openai-key-here\nANTHROPIC_API_KEY=\n",
        0o644,
    );
    write(
        &repo.join("node_modules/pkg/.env"),
        &format!("OPENAI_API_KEY={}-{}-{}\n", "sk", "proj", rand_alnum(6, 120)),
        0o644,
    );

    Fixture {
        home,
        keys: vec![anthropic, openai, groq, mistral, google],
    }
}

impl Fixture {
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("keysweep").unwrap();
        let h = self.home.path();
        c.env("KEYSWEEP_HOME", h).env("NO_COLOR", "1");
        c
    }
    fn scan_args(&self) -> Vec<String> {
        let h = self.home.path();
        vec![
            "--path".into(),
            h.join("code").display().to_string(),
            "--path".into(),
            h.join("Library/CloudStorage").display().to_string(),
        ]
    }
    fn assert_no_leak(&self, out: &[u8]) {
        let text = String::from_utf8_lossy(out);
        for k in &self.keys {
            assert!(!text.contains(k.as_str()), "raw key leaked in output");
            assert!(!text.contains(&k[k.len() - 12..]), "key suffix leaked in output");
        }
    }
}

fn scan_json(fx: &Fixture) -> serde_json::Value {
    let out = fx
        .cmd()
        .arg("scan")
        .args(fx.scan_args())
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    fx.assert_no_leak(&out.stdout);
    fx.assert_no_leak(&out.stderr);
    serde_json::from_slice(&out.stdout).unwrap()
}

fn find<'a>(v: &'a serde_json::Value, provider: &str) -> &'a serde_json::Value {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["provider"] == provider)
        .unwrap_or_else(|| panic!("no {provider} finding"))
}

fn risk_types(f: &serde_json::Value) -> Vec<String> {
    f["risks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["type"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn scan_finds_every_planted_key_with_right_risks() {
    let fx = fixture();
    let v = scan_json(&fx);
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 5, "{v:#}");

    let a = find(&v, "anthropic");
    assert_eq!(a["tool"], "Shell profile");
    assert_eq!(a["line"], 2);
    assert!(risk_types(a).contains(&"shell_exported".into()));
    assert!(risk_types(a).contains(&"world_readable".into()));
    assert_eq!(a["severity"], "high");
    assert!(a["fingerprint"].as_str().unwrap().starts_with("sk-ant-api03-…"));

    let o = find(&v, "openai");
    assert_eq!(o["tool"], "OpenCode auth store");
    assert_eq!(o["severity"], "low");

    for p in ["groq", "mistral"] {
        let f = find(&v, p);
        assert!(risk_types(f).contains(&"in_git_history".into()), "{p}: {f:#}");
        assert!(!risk_types(f).contains(&"tracked_in_git".into()));
        assert_eq!(f["severity"], "critical");
    }
    assert_eq!(find(&v, "mistral")["confidence"], "medium");

    let g = find(&v, "google");
    assert!(g["tool"].as_str().unwrap().starts_with("Cursor MCP project"));
    assert!(risk_types(g).contains(&"cloud_synced".into()));
}

#[test]
fn table_and_sarif_never_leak() {
    let fx = fixture();
    for format in ["table", "sarif"] {
        let out = fx
            .cmd()
            .arg("scan")
            .args(fx.scan_args())
            .args(["--format", format])
            .output()
            .unwrap();
        assert!(out.status.success());
        fx.assert_no_leak(&out.stdout);
        fx.assert_no_leak(&out.stderr);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("console.anthropic.com") || format == "sarif");
    }
}

#[test]
fn fail_on_and_min_severity() {
    let fx = fixture();
    fx.cmd()
        .arg("scan")
        .args(fx.scan_args())
        .args(["--fail-on", "critical"])
        .assert()
        .code(1);
    fx.cmd()
        .arg("scan")
        .arg("--no-projects")
        .args(["--fail-on", "critical"])
        .assert()
        .success();
    let out = fx
        .cmd()
        .arg("scan")
        .args(fx.scan_args())
        .args(["--min-severity", "critical", "-f", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 3);
}

#[test]
fn fix_dry_run_changes_nothing_and_perms_apply_works() {
    let fx = fixture();
    let zshrc = fx.home.path().join(".zshrc");
    let before = fs::read_to_string(&zshrc).unwrap();
    let id = find(&scan_json(&fx), "anthropic")["id"].as_str().unwrap().to_string();

    let out = fx.cmd().args(["fix", "--no-projects", "--id", &id]).output().unwrap();
    assert!(out.status.success());
    fx.assert_no_leak(&out.stdout);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Dry run"));
    assert_eq!(fs::read_to_string(&zshrc).unwrap(), before);
    assert_eq!(fs::metadata(&zshrc).unwrap().permissions().mode() & 0o777, 0o644);

    let out = fx
        .cmd()
        .args(["fix", "--no-projects", "--perms", "--apply", "--id", &id])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(fs::metadata(&zshrc).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(&zshrc).unwrap(), before);
}

#[test]
fn fix_requires_selection() {
    let fx = fixture();
    fx.cmd().args(["fix", "--no-projects"]).assert().code(2);
}

#[test]
fn custom_registry_adds_locations() {
    let fx = fixture();
    let key = format!("{}-{}-{}", "sk", "proj", rand_alnum(77, 120));
    write(&fx.home.path().join(".mytool/creds"), &format!("key = \"{key}\"\n"), 0o600);
    let reg = fx.home.path().join("extra.toml");
    fs::write(&reg, "[[tool]]\nname = \"MyTool\"\npaths = [\"~/.mytool/creds\"]\n").unwrap();
    let out = fx
        .cmd()
        .args(["scan", "--no-projects", "-f", "json", "--registry"])
        .arg(&reg)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\"MyTool\""));
    assert!(!text.contains(&key));
}
