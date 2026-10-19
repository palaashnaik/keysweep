use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use keysweep::fix::{self, Action, Applier, Keychain, Manifest, Rewrite};
use keysweep::registry::{self, Registry};
use keysweep::report;
use keysweep::risk::Severity;
use keysweep::scan::{self, Finding, ScanOptions};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "keysweep", version, about = "Find and lock down AI tool API keys on your laptop")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan known AI tool locations, shell profiles and project .env files
    Scan(ScanArgs),
    /// Tighten permissions and move keys into the macOS Keychain (dry run unless --apply)
    Fix(FixArgs),
    /// Print `export` lines that load keysweep-managed keys from the Keychain
    Env,
    /// List the locations keysweep checks
    Locations {
        /// Also show locations that don't exist on this machine
        #[arg(long)]
        all: bool,
    },
    /// Print revoke and spend-limit pages for every supported provider
    Links,
}

#[derive(Args, Clone)]
struct ScanArgs {
    /// Project directory to search for .env / MCP config files (repeatable).
    /// Defaults to common code folders under your home directory.
    #[arg(long = "path", short = 'p', value_name = "DIR")]
    paths: Vec<PathBuf>,
    /// Only check the known tool locations, skip walking project folders
    #[arg(long)]
    no_projects: bool,
    /// Skip git tracked/history checks
    #[arg(long)]
    no_git: bool,
    /// Max directory depth when walking project folders
    #[arg(long, default_value_t = 6)]
    depth: usize,
    /// Extra registry TOML with more tool locations
    #[arg(long, value_name = "FILE")]
    registry: Option<PathBuf>,
    /// Hide findings below this severity
    #[arg(long, value_enum, default_value_t = Severity::Low)]
    min_severity: Severity,
    /// Output format
    #[arg(long, short = 'f', value_enum, default_value_t = Format::Table)]
    format: Format,
    /// Exit with status 1 if any finding is at or above this severity
    #[arg(long, value_enum)]
    fail_on: Option<Severity>,
    /// Treat DIR as the home directory (for testing; also KEYSWEEP_HOME)
    #[arg(long, hide = true)]
    home: Option<PathBuf>,
}

#[derive(Args)]
struct FixArgs {
    #[command(flatten)]
    scan: ScanArgs,
    /// Finding ID(s) from `keysweep scan` (repeatable)
    #[arg(long = "id")]
    ids: Vec<String>,
    /// Act on every finding (after --min-severity filtering)
    #[arg(long, conflicts_with = "ids")]
    all: bool,
    /// chmod 600 files that other users can read
    #[arg(long)]
    perms: bool,
    /// Move keys into the macOS Keychain and rewrite the file to reference them
    #[arg(long)]
    keychain: bool,
    /// Actually make changes (default is a dry run)
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    Sarif,
}

fn home_dir(arg: &Option<PathBuf>) -> Result<PathBuf> {
    match arg.clone().or_else(|| {
        std::env::var_os("KEYSWEEP_HOME")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }) {
        Some(h) => Ok(h),
        None => bail!("cannot determine home directory; pass --home"),
    }
}

fn run_scan(args: &ScanArgs) -> Result<(PathBuf, Vec<Finding>)> {
    let home = home_dir(&args.home)?;
    let roots = if args.no_projects {
        Vec::new()
    } else if args.paths.is_empty() {
        ScanOptions::default_roots(&home)
    } else {
        args.paths.clone()
    };
    let opts = ScanOptions {
        home: home.clone(),
        roots,
        registry: Registry::load(args.registry.as_deref())?,
        check_git: !args.no_git,
        max_depth: args.depth,
    };
    let findings = scan::scan(&opts).into_iter().filter(|f| f.severity >= args.min_severity).collect();
    Ok((home, findings))
}

fn color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn cmd_scan(args: ScanArgs) -> Result<ExitCode> {
    let (home, findings) = run_scan(&args)?;
    match args.format {
        Format::Json => println!("{}", report::json(&findings)),
        Format::Sarif => println!("{}", report::sarif(&findings)),
        Format::Table if findings.is_empty() => println!("No plaintext AI provider keys found."),
        Format::Table => {
            println!("{}", report::table(&findings, &home, color()));
            println!("{}\n", report::summary(&findings));
            println!("Revoke or cap spend for the providers above:\n{}", report::links(&findings));
            println!("Next: `keysweep fix --id <ID>` (or --all) to preview fixes, then add --apply.");
        }
    }
    let fail = args.fail_on.is_some_and(|t| findings.iter().any(|f| f.severity >= t));
    Ok(if fail { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn cmd_fix(mut args: FixArgs) -> Result<ExitCode> {
    if !args.perms && !args.keychain {
        args.perms = true;
        args.keychain = true;
    }
    if args.ids.is_empty() && !args.all {
        bail!("choose findings with --id <ID> (from `keysweep scan`) or --all");
    }
    let (home, findings) = run_scan(&args.scan)?;
    let selected: Vec<&Finding> = findings
        .iter()
        .filter(|f| args.all || args.ids.iter().any(|id| id == &f.id))
        .collect();
    for id in &args.ids {
        if !findings.iter().any(|f| &f.id == id) {
            eprintln!("warning: no finding with id {id}");
        }
    }
    if selected.is_empty() {
        println!("Nothing to fix.");
        return Ok(ExitCode::SUCCESS);
    }

    let actions = fix::plan(&selected, args.perms, args.keychain);
    let state_dir = home.join(".keysweep");
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let store = Keychain;
    let mut applier = Applier::new(&store, &state_dir, &run_id);
    let mut failures = 0;
    let mut gui_refs = false;

    println!(
        "{}",
        if args.apply {
            "Applying fixes:"
        } else {
            "Dry run. These changes would be made (re-run with --apply):"
        }
    );
    for action in &actions {
        let (target, desc) = match action {
            Action::Chmod { path, mode } => (report::tilde(path, &home), format!("chmod {mode} -> 0600")),
            Action::Move { finding: f, env, rewrite } => {
                let how = match rewrite {
                    Rewrite::ShellLookup => "replace value with a Keychain lookup".to_string(),
                    Rewrite::CommentOut => "comment out the line (load it with `keysweep env`)".to_string(),
                    Rewrite::EnvRef(r) => {
                        gui_refs = true;
                        format!("replace value with {r}")
                    }
                    Rewrite::Manual(why) => format!("store only; manual step: {why}"),
                };
                (
                    format!("{}:{} [{}]", report::tilde(&f.path, &home), f.line, f.fingerprint),
                    format!("Keychain {env}, {how}"),
                )
            }
        };
        if !args.apply {
            println!("  - {target}\n      {desc}");
            continue;
        }
        match applier.apply(action) {
            Ok(o) => {
                println!("  ok   {target}\n      {}", o.message);
                if let Some(b) = o.backup {
                    println!(
                        "      backup: {} (contains the original key; delete it once things work)",
                        report::tilde(&b, &home)
                    );
                }
            }
            Err(e) => {
                failures += 1;
                println!("  FAIL {target}\n      {e:#}");
            }
        }
    }

    if args.keychain {
        println!("\nKeys moved to the Keychain are loaded into your shell by adding this line to ~/.zshrc:");
        println!("  eval \"$(keysweep env)\"");
        if gui_refs {
            println!("Apps launched from the Dock (Cursor, VS Code, Claude Desktop) don't read ~/.zshrc; start them from a terminal");
            println!("or set the variable with `launchctl setenv` so ${{...}} references resolve.");
        }
    }
    let leaked: Vec<&Finding> = selected.iter().copied().filter(|f| f.severity == Severity::Critical).collect();
    if !leaked.is_empty() {
        println!(
            "\nThese keys were committed or synced, so moving them is not enough. Rotate them:\n{}",
            report::links(leaked)
        );
    }
    Ok(if failures > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn cmd_env() -> Result<ExitCode> {
    let home = home_dir(&None)?;
    let manifest = Manifest::load(&home.join(".keysweep/manifest.json"))?;
    print!("{}", manifest.exports(&Keychain));
    Ok(ExitCode::SUCCESS)
}

fn cmd_locations(all: bool) -> Result<ExitCode> {
    let home = home_dir(&None)?;
    for tool in Registry::builtin().tools {
        let mut lines = Vec::new();
        for p in &tool.paths {
            let found = registry::resolve(p, &home);
            if !found.is_empty() {
                lines.extend(found.iter().map(|f| format!("  [found]   {}", report::tilde(f, &home))));
            } else if all {
                lines.push(format!("  [missing] {p}"));
            }
        }
        if !lines.is_empty() {
            println!("{}\n{}", tool.name, lines.join("\n"));
        }
    }
    println!("Project folders searched for .env / MCP configs by default:");
    for d in scan::DEFAULT_PROJECT_DIRS {
        let p = home.join(d);
        if all || p.is_dir() {
            println!("  [{}] ~/{d}", if p.is_dir() { "found" } else { "missing" });
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_links() -> Result<ExitCode> {
    for p in keysweep::detect::PROVIDERS.iter().filter(|p| p.id != "unknown") {
        println!("{:<20} revoke: {}", p.name, p.revoke_url);
        if let Some(l) = p.limits_url {
            println!("{:<20} limits: {}", "", l);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        None => cmd_scan(ScanArgs::parse_from_defaults()),
        Some(Command::Scan(a)) => cmd_scan(a),
        Some(Command::Fix(a)) => cmd_fix(a),
        Some(Command::Env) => cmd_env(),
        Some(Command::Locations { all }) => cmd_locations(all),
        Some(Command::Links) => cmd_links(),
    };
    result.unwrap_or_else(|e| {
        eprintln!("keysweep: {e:#}");
        ExitCode::from(2)
    })
}

impl ScanArgs {
    fn parse_from_defaults() -> Self {
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: ScanArgs,
        }
        Wrapper::parse_from(["keysweep"]).args
    }
}
