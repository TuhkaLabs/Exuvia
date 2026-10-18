use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

/// Tokens that add no identifying value when matching directory or key names.
const GENERIC_TOKENS: &[&str] = &[
    "app",
    "application",
    "free",
    "portable",
    "premium",
    "pro",
    "setup",
    "update",
    "version",
    "win",
    "windows",
    "x64",
    "x86",
    "x86_64",
];

const LEGAL_SUFFIXES: &[&str] = &[
    "ab",
    "ag",
    "as",
    "bv",
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "inc",
    "incorporated",
    "limited",
    "llc",
    "ltd",
    "oy",
    "plc",
    "pte",
    "sarl",
    "sa",
    "software",
    "technologies",
    "technology",
];

pub fn home_dir() -> PathBuf {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile);
    }
    let drive = std::env::var_os("HOMEDRIVE").unwrap_or_default();
    let path = std::env::var_os("HOMEPATH").unwrap_or_default();
    let combined = format!("{}{}", drive.to_string_lossy(), path.to_string_lossy());
    if combined.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(combined)
    }
}

/// Expand Windows `%VARIABLE%` placeholders and a leading `~`.
pub fn expand_env(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }

        let mut name = String::new();
        let mut closed = false;
        for next in chars.by_ref() {
            if next == '%' {
                closed = true;
                break;
            }
            name.push(next);
        }

        if closed && !name.is_empty() {
            match std::env::var(&name) {
                Ok(value) => output.push_str(&value),
                Err(_) => {
                    output.push('%');
                    output.push_str(&name);
                    output.push('%');
                }
            }
        } else if closed {
            output.push_str("%%");
        } else {
            output.push('%');
            output.push_str(&name);
        }
    }

    if let Some(rest) = output.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/') {
            return format!("{}{}", home_dir().display(), rest);
        }
    }

    output
}

/// Make a path absolute and resolve `.`/`..` without touching the filesystem.
pub fn lexical_absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path_clean::clean(path)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        path_clean::clean(cwd.join(path))
    }
}

/// Canonicalize when possible, otherwise normalize lexically. Windows verbatim
/// prefixes are removed so comparisons and user-facing output stay readable.
pub fn resolve_path(path: &Path) -> PathBuf {
    let resolved = if path.exists() {
        std::fs::canonicalize(path).unwrap_or_else(|_| lexical_absolute(path))
    } else {
        lexical_absolute(path)
    };
    strip_verbatim_prefix(&resolved)
}

pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// Lowercase, backslash-normalized key used for path containment checks.
pub fn normalize_path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = strip_verbatim_text(&text);
    let text = text.trim_end_matches('\\');
    if text.is_empty() {
        "\\".to_string()
    } else {
        text.to_lowercase()
    }
}

fn strip_verbatim_text(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text.to_string()
    }
}

/// True when `candidate` equals `root` or lives underneath it.
pub fn is_within(candidate: &Path, root: &Path) -> bool {
    let candidate = normalize_path_key(candidate);
    let root = normalize_path_key(root);
    let root = root.trim_end_matches('\\');
    let candidate = candidate.trim_end_matches('\\');
    if root.is_empty() {
        return true;
    }
    candidate == root || candidate.starts_with(&format!("{root}\\"))
}

/// NFKC + lowercase + alphanumeric-only form used for fuzzy matching.
pub fn normalize_name(input: &str) -> String {
    input
        .replace(['\u{2122}', '\u{00AE}', '\u{00A9}'], "")
        .nfkc()
        .flat_map(|ch| ch.to_lowercase())
        .filter(|ch| ch.is_alphanumeric())
        .collect()
}

fn tokenize(input: &str) -> Vec<String> {
    input
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
        .collect()
}

fn is_version_token(token: &str) -> bool {
    if token.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    let without_v = token.strip_prefix('v').unwrap_or(token);
    without_v.contains('.')
        && without_v
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

/// Candidate normalized names for an application, used by the heuristic scanner.
pub fn name_variants(name: &str) -> Vec<String> {
    let mut variants = BTreeSet::new();

    let base = normalize_name(name);
    if base.len() >= 3 {
        variants.insert(base);
    }

    let stripped: String = tokenize(name)
        .into_iter()
        .filter(|token| !is_version_token(token) && !GENERIC_TOKENS.contains(&token.as_str()))
        .map(|token| normalize_name(&token))
        .collect();
    if stripped.len() >= 3 {
        variants.insert(stripped);
    }

    variants.into_iter().collect()
}

/// Candidate normalized publisher names. Legal suffixes are removed so
/// "Example Corp." matches a directory called "Example".
pub fn publisher_variants(publisher: &str) -> Vec<String> {
    let mut variants = BTreeSet::new();

    let base = normalize_name(publisher);
    if base.len() >= 3 {
        variants.insert(base);
    }

    let stripped: String = tokenize(publisher)
        .into_iter()
        .filter(|token| !LEGAL_SUFFIXES.contains(&token.as_str()))
        .map(|token| normalize_name(&token))
        .collect();
    if stripped.len() >= 3 {
        variants.insert(stripped);
    }

    variants.into_iter().collect()
}

/// Refuse to operate on symlinks, junctions and other reparse points (FR-20).
pub fn is_reparse_or_symlink(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_variables_and_leaves_unknown_ones() {
        std::env::set_var("EXUVIA_TEST_ROOT", r"C:\Example");
        assert_eq!(expand_env(r"%EXUVIA_TEST_ROOT%\data"), r"C:\Example\data");
        assert_eq!(
            expand_env(r"%EXUVIA_MISSING%\data"),
            r"%EXUVIA_MISSING%\data"
        );
    }

    #[test]
    fn normalizes_names_for_matching() {
        assert_eq!(normalize_name("Example Editor™"), "exampleeditor");
        assert_eq!(normalize_name("Über-App"), "überapp");
    }

    #[test]
    fn generates_variants_without_versions_and_generic_words() {
        let variants = name_variants("Example Editor 2024");
        assert!(variants.contains(&"exampleeditor2024".to_string()));
        assert!(variants.contains(&"exampleeditor".to_string()));
    }

    #[test]
    fn strips_legal_publisher_suffixes() {
        let variants = publisher_variants("Example Technologies, Inc.");
        assert!(variants.contains(&"example".to_string()));
    }

    #[test]
    fn detects_path_containment() {
        let root = Path::new(r"C:\Users\Test\AppData\Roaming");
        assert!(is_within(
            Path::new(r"C:\Users\Test\AppData\Roaming\App"),
            root
        ));
        assert!(!is_within(
            Path::new(r"C:\Users\Test\AppData\RoamingOther"),
            root
        ));
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(15 * 1024 * 1024), "15 MB");
    }
}
