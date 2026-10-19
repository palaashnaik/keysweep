//! Provider key-format detectors plus a context (variable-name) detector with
//! entropy and placeholder filtering.

use crate::secret::Secret;
use regex::Regex;
use std::sync::LazyLock;

pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    /// Conventional environment variable for this provider's key.
    pub env_var: &'static str,
    /// Substrings of a variable name that identify this provider.
    pub name_hints: &'static [&'static str],
    pub revoke_url: &'static str,
    pub limits_url: Option<&'static str>,
}

pub static PROVIDERS: &[Provider] = &[
    Provider {
        id: "anthropic",
        name: "Anthropic",
        env_var: "ANTHROPIC_API_KEY",
        name_hints: &["ANTHROPIC", "CLAUDE"],
        revoke_url: "https://console.anthropic.com/settings/keys",
        limits_url: Some("https://console.anthropic.com/settings/limits"),
    },
    Provider {
        id: "openai",
        name: "OpenAI",
        env_var: "OPENAI_API_KEY",
        name_hints: &["OPENAI"],
        revoke_url: "https://platform.openai.com/api-keys",
        limits_url: Some("https://platform.openai.com/settings/organization/limits"),
    },
    Provider {
        id: "google",
        name: "Google AI / Gemini",
        env_var: "GEMINI_API_KEY",
        name_hints: &["GEMINI", "GOOGLE"],
        revoke_url: "https://aistudio.google.com/apikey",
        limits_url: Some("https://console.cloud.google.com/billing"),
    },
    Provider {
        id: "openrouter",
        name: "OpenRouter",
        env_var: "OPENROUTER_API_KEY",
        name_hints: &["OPENROUTER"],
        revoke_url: "https://openrouter.ai/settings/keys",
        limits_url: Some("https://openrouter.ai/settings/keys"),
    },
    Provider {
        id: "groq",
        name: "Groq",
        env_var: "GROQ_API_KEY",
        name_hints: &["GROQ"],
        revoke_url: "https://console.groq.com/keys",
        limits_url: Some("https://console.groq.com/settings/limits"),
    },
    Provider {
        id: "xai",
        name: "xAI",
        env_var: "XAI_API_KEY",
        name_hints: &["XAI", "GROK"],
        revoke_url: "https://console.x.ai",
        limits_url: None,
    },
    Provider {
        id: "mistral",
        name: "Mistral",
        env_var: "MISTRAL_API_KEY",
        name_hints: &["MISTRAL"],
        revoke_url: "https://console.mistral.ai/api-keys",
        limits_url: Some("https://admin.mistral.ai/plateforme/limits"),
    },
    Provider {
        id: "deepseek",
        name: "DeepSeek",
        env_var: "DEEPSEEK_API_KEY",
        name_hints: &["DEEPSEEK"],
        revoke_url: "https://platform.deepseek.com/api_keys",
        limits_url: None,
    },
    Provider {
        id: "cohere",
        name: "Cohere",
        env_var: "COHERE_API_KEY",
        name_hints: &["COHERE", "CO_API_KEY"],
        revoke_url: "https://dashboard.cohere.com/api-keys",
        limits_url: None,
    },
    Provider {
        id: "together",
        name: "Together AI",
        env_var: "TOGETHER_API_KEY",
        name_hints: &["TOGETHER"],
        revoke_url: "https://api.together.ai/settings/api-keys",
        limits_url: None,
    },
    Provider {
        id: "fireworks",
        name: "Fireworks",
        env_var: "FIREWORKS_API_KEY",
        name_hints: &["FIREWORKS"],
        revoke_url: "https://fireworks.ai/account/api-keys",
        limits_url: None,
    },
    Provider {
        id: "perplexity",
        name: "Perplexity",
        env_var: "PERPLEXITY_API_KEY",
        name_hints: &["PERPLEXITY", "PPLX"],
        revoke_url: "https://www.perplexity.ai/settings/api",
        limits_url: None,
    },
    Provider {
        id: "replicate",
        name: "Replicate",
        env_var: "REPLICATE_API_TOKEN",
        name_hints: &["REPLICATE"],
        revoke_url: "https://replicate.com/account/api-tokens",
        limits_url: None,
    },
    Provider {
        id: "huggingface",
        name: "Hugging Face",
        env_var: "HF_TOKEN",
        name_hints: &["HUGGINGFACE", "HF_TOKEN", "HF_API"],
        revoke_url: "https://huggingface.co/settings/tokens",
        limits_url: None,
    },
    Provider {
        id: "elevenlabs",
        name: "ElevenLabs",
        env_var: "ELEVENLABS_API_KEY",
        name_hints: &["ELEVEN"],
        revoke_url: "https://elevenlabs.io/app/settings/api-keys",
        limits_url: None,
    },
    Provider {
        id: "github",
        name: "GitHub",
        env_var: "GITHUB_TOKEN",
        name_hints: &["GITHUB", "GH_TOKEN", "COPILOT"],
        revoke_url: "https://github.com/settings/tokens",
        limits_url: None,
    },
    Provider {
        id: "unknown",
        name: "Unknown",
        env_var: "API_KEY",
        name_hints: &[],
        revoke_url: "",
        limits_url: None,
    },
];

pub fn provider(id: &str) -> &'static Provider {
    PROVIDERS.iter().find(|p| p.id == id).unwrap_or_else(|| PROVIDERS.last().unwrap())
}

/// Guess a provider from a variable / key name such as `OPENAI_API_KEY`.
pub fn provider_from_name(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    PROVIDERS
        .iter()
        .find(|p| p.name_hints.iter().any(|h| upper.contains(h)))
        .map(|p| p.id)
}

struct Pattern {
    provider: &'static str,
    re: Regex,
}

/// Each pattern captures the public prefix as group `p`; the whole match is the key.
/// Order matters: more specific prefixes first.
static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let defs: &[(&str, &str)] = &[
        ("anthropic", r"\b(?P<p>sk-ant-[a-z]+[0-9]{2}-)[A-Za-z0-9_\-]{32,}"),
        ("openrouter", r"\b(?P<p>sk-or-v1-)[a-f0-9]{64}"),
        ("openai", r"\b(?P<p>sk-(?:proj|svcacct|admin)-)[A-Za-z0-9_\-]{32,}"),
        ("openai", r"\b(?P<p>sk-)[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        ("google", r"\b(?P<p>AIza)[0-9A-Za-z_\-]{35}"),
        ("groq", r"\b(?P<p>gsk_)[A-Za-z0-9]{52}"),
        ("xai", r"\b(?P<p>xai-)[A-Za-z0-9]{70,}"),
        ("huggingface", r"\b(?P<p>hf_)[A-Za-z0-9]{34,}"),
        ("replicate", r"\b(?P<p>r8_)[A-Za-z0-9]{37}"),
        ("perplexity", r"\b(?P<p>pplx-)[A-Za-z0-9]{48}"),
        ("fireworks", r"\b(?P<p>fw_)[A-Za-z0-9]{24,}"),
        ("elevenlabs", r"\b(?P<p>sk_)[a-f0-9]{48}"),
        ("github", r"\b(?P<p>github_pat_)[A-Za-z0-9_]{60,}"),
        ("github", r"\b(?P<p>gh[pousr]_)[A-Za-z0-9]{36}"),
    ];
    defs.iter()
        .map(|(provider, re)| Pattern {
            provider,
            re: Regex::new(re).expect("valid pattern"),
        })
        .collect()
});

/// `NAME = value`, `export NAME="value"`, `"name": "value"`, `name: value`.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?P<name>[A-Za-z0-9_]*(?:api[_-]?key|token|secret|access[_-]?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']?(?P<value>[A-Za-z0-9_\-\.]{20,})"#,
    )
    .expect("valid assignment regex")
});

const PLACEHOLDER_WORDS: &[&str] = &[
    "your",
    "xxxx",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "replace",
    "dummy",
    "sample",
    "insert",
    "redacted",
    "here",
    "fake",
    "todo",
    "secret_key",
    "api_key",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Matched a provider-specific key format.
    High,
    /// Matched a credential-looking assignment with a high-entropy value.
    Medium,
}

#[derive(Debug)]
pub struct Detection {
    pub provider: &'static str,
    pub secret: Secret,
    /// Public, non-random part of the key used in fingerprints.
    pub prefix: String,
    pub var_name: Option<String>,
    pub confidence: Confidence,
    /// Byte range of the secret inside the line.
    pub span: (usize, usize),
}

pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if PLACEHOLDER_WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    // Long runs of one character: sk-ant-api03-aaaaaaaa...
    let bytes = value.as_bytes();
    let mut run = 1;
    for w in bytes.windows(2) {
        run = if w[0] == w[1] { run + 1 } else { 1 };
        if run >= 6 {
            return true;
        }
    }
    false
}

/// Name assigned immediately before a value: `NAME=`, `"name": "`, `name: `.
static NAME_BEFORE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?P<name>[A-Za-z_][A-Za-z0-9_\-]*)["']?\s*[:=]\s*["']?$"#).expect("valid name regex"));

fn name_before(line: &str, start: usize) -> Option<String> {
    NAME_BEFORE.captures(&line[..start]).map(|c| c["name"].to_string())
}

/// Scan one line. `default_provider` is the tool's usual provider, used when a
/// context match has no provider hint in its variable name.
pub fn scan_line(line: &str, default_provider: Option<&'static str>) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    let overlaps = |out: &Vec<Detection>, s: usize, e: usize| out.iter().any(|d| s < d.span.1 && d.span.0 < e);

    for pat in PATTERNS.iter() {
        for caps in pat.re.captures_iter(line) {
            let m = caps.get(0).unwrap();
            if overlaps(&out, m.start(), m.end()) {
                continue;
            }
            let value = m.as_str();
            let prefix = caps.name("p").map(|p| p.as_str()).unwrap_or("");
            let body = &value[prefix.len()..];
            if looks_like_placeholder(body) || shannon_entropy(body) < 3.0 {
                continue;
            }
            out.push(Detection {
                provider: pat.provider,
                secret: Secret::new(value),
                prefix: prefix.to_string(),
                var_name: name_before(line, m.start()),
                confidence: Confidence::High,
                span: (m.start(), m.end()),
            });
        }
    }

    for caps in ASSIGNMENT.captures_iter(line) {
        let v = caps.name("value").unwrap();
        if overlaps(&out, v.start(), v.end()) {
            continue;
        }
        let value = v.as_str();
        let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
        let has_digit = value.bytes().any(|b| b.is_ascii_digit());
        if !has_alpha || !has_digit || looks_like_placeholder(value) || shannon_entropy(value) < 3.5 {
            continue;
        }
        // Dotted values are usually versions, hostnames or JWT-free identifiers.
        if value.contains("..") || value.matches('.').count() > 2 {
            continue;
        }
        let name = caps["name"].to_string();
        let provider = provider_from_name(&name).or(default_provider).unwrap_or("unknown");
        out.push(Detection {
            provider,
            secret: Secret::new(value),
            prefix: String::new(),
            var_name: Some(name),
            confidence: Confidence::Medium,
            span: (v.start(), v.end()),
        });
    }

    out.sort_by_key(|d| d.span.0);
    out
}

#[cfg(test)]
pub mod testkeys {
    //! Fake keys are assembled at runtime so that no key-shaped literal lives in
    //! the source tree (and push-protection scanners stay quiet).

    /// Deterministic pseudo-random alphanumeric string.
    pub fn rand_alnum(seed: u64, len: usize) -> String {
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

    pub fn rand_hex(seed: u64, len: usize) -> String {
        rand_alnum(seed, len * 2)
            .bytes()
            .map(|b| char::from_digit((b % 16) as u32, 16).unwrap())
            .take(len)
            .collect()
    }

    pub fn anthropic(seed: u64) -> String {
        format!("{}-{}-{}-{}", "sk", "ant", "api03", rand_alnum(seed, 93))
    }
    pub fn openai(seed: u64) -> String {
        format!("{}-{}-{}", "sk", "proj", rand_alnum(seed, 120))
    }
    pub fn google(seed: u64) -> String {
        ["AI", "za"].concat() + &rand_alnum(seed, 35)
    }
    pub fn openrouter(seed: u64) -> String {
        format!("{}-{}-{}-{}", "sk", "or", "v1", rand_hex(seed, 64))
    }
    pub fn groq(seed: u64) -> String {
        format!("{}_{}", "gsk", rand_alnum(seed, 52))
    }
}

#[cfg(test)]
mod tests {
    use super::testkeys::*;
    use super::*;

    #[test]
    fn detects_provider_formats() {
        let cases = [
            (anthropic(1), "anthropic", "sk-ant-api03-"),
            (openai(2), "openai", "sk-proj-"),
            (google(3), "google", "AIza"),
            (openrouter(4), "openrouter", "sk-or-v1-"),
            (groq(5), "groq", "gsk_"),
        ];
        for (key, provider, prefix) in cases {
            let line = format!("export SOME_VAR=\"{key}\"");
            let d = scan_line(&line, None);
            assert_eq!(d.len(), 1, "{provider}: {d:?}");
            assert_eq!(d[0].provider, provider);
            assert_eq!(d[0].prefix, prefix);
            assert_eq!(d[0].secret.expose(), key);
            assert_eq!(d[0].confidence, Confidence::High);
            assert_eq!(d[0].var_name.as_deref(), Some("SOME_VAR"));
        }
    }

    #[test]
    fn json_line_with_two_keys() {
        let line = format!(
            r#"{{"anthropic":{{"apiKey":"{}"}},"openai":{{"apiKey":"{}"}}}}"#,
            anthropic(7),
            openai(8)
        );
        let d = scan_line(&line, None);
        assert_eq!(d.iter().map(|d| d.provider).collect::<Vec<_>>(), ["anthropic", "openai"]);
    }

    #[test]
    fn context_detector_uses_variable_name() {
        let line = format!("MISTRAL_API_KEY={}", rand_alnum(9, 32));
        let d = scan_line(&line, None);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].provider, "mistral");
        assert_eq!(d[0].confidence, Confidence::Medium);
        assert_eq!(d[0].prefix, "");
    }

    #[test]
    fn context_detector_falls_back_to_tool_provider() {
        let line = format!(r#""apiKey": "{}""#, rand_alnum(10, 40));
        assert_eq!(scan_line(&line, Some("deepseek"))[0].provider, "deepseek");
        assert_eq!(scan_line(&line, None)[0].provider, "unknown");
    }

    #[test]
    fn ignores_placeholders_and_references() {
        for line in [
            "OPENAI_API_KEY=your-openai-api-key-goes-here",
            "ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}",
            r#"export OPENAI_API_KEY="$(security find-generic-password -s keysweep -a OPENAI_API_KEY -w)""#,
            r#""apiKey": "{env:ANTHROPIC_API_KEY}""#,
            "MAX_TOKENS=4096",
            "token_count: 1234567890123456789012",
            "GITHUB_TOKEN_SCOPE=read_packages_and_more_scopes",
        ] {
            assert!(scan_line(line, None).is_empty(), "false positive on {line}");
        }
    }

    #[test]
    fn entropy_sanity() {
        assert!(shannon_entropy("aaaaaaaa") < 0.01);
        assert!(shannon_entropy(&rand_alnum(1, 40)) > 4.0);
    }
}
