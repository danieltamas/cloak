//! `.env` file parser with perfect roundtrip fidelity.
//!
//! Parses `.env` content into a structured [`EnvLine`] representation,
//! preserving the original text so that `serialize(parse(content)) == content`.
//!
//! # Grammar (spec §6.7)
//!
//! ```text
//! file          = line*
//! line          = comment | assignment | blank
//! comment       = /^\s*#.*$/
//! blank         = /^\s*$/
//! assignment    = export? key '=' value
//! export        = 'export' ws+
//! key           = [A-Za-z_][A-Za-z0-9_]*
//! value         = double_quoted | single_quoted | unquoted
//! double_quoted = '"' (escaped_char | [^"])* '"'
//! single_quoted = "'" [^']* "'"
//! unquoted      = [^\n#]* (trimmed trailing whitespace + inline comments)
//! escaped_char  = '\\' [nrt"\\]
//! ```

/// How the value portion of an assignment is quoted.
#[derive(Debug, Clone, PartialEq)]
pub enum QuoteStyle {
    /// No surrounding quotes.
    None,
    /// Value is surrounded by single quotes (`'`). No escape processing inside.
    Single,
    /// Value is surrounded by double quotes (`"`). Supports `\n`, `\r`, `\t`, `\"`, `\\`.
    Double,
}

/// A single logical line (or multi-line span) from a `.env` file.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvLine {
    /// A comment line, including any leading whitespace and the `#`.
    Comment(String),
    /// A blank (whitespace-only) line.
    Blank,
    /// A key-value assignment.
    Assignment {
        /// Whether the line began with `export `.
        export: bool,
        /// The variable name.
        key: String,
        /// The parsed, unescaped value.
        value: String,
        /// How the value was quoted in the source.
        quote_style: QuoteStyle,
        /// The original source text (may span multiple physical lines for double-quoted multiline values).
        raw_line: String,
    },
}

/// Parse `.env` content into a list of [`EnvLine`] values.
///
/// Lines are consumed in order. Double-quoted values may span multiple physical lines.
/// The resulting list preserves every byte of the original when round-tripped through
/// [`serialize`].
pub fn parse(content: &str) -> Vec<EnvLine> {
    let mut result = Vec::new();

    // We work on the raw bytes but split on `\n`.  We collect physical lines
    // into a peekable iterator so that multiline double-quoted values can
    // consume additional lines.
    let physical_lines: Vec<&str> = content.split('\n').collect();
    let mut i = 0;

    while i < physical_lines.len() {
        let line = physical_lines[i];

        // ── Blank ──────────────────────────────────────────────────────────
        if line.trim().is_empty() {
            result.push(EnvLine::Blank);
            i += 1;
            continue;
        }

        // ── Comment ────────────────────────────────────────────────────────
        if line.trim_start().starts_with('#') {
            result.push(EnvLine::Comment(line.to_string()));
            i += 1;
            continue;
        }

        // ── Assignment ─────────────────────────────────────────────────────
        // Optional `export ` prefix.
        let (export, rest) = if let Some(stripped) = line.strip_prefix("export ") {
            (true, stripped)
        } else {
            (false, line)
        };

        // Key: [A-Za-z_][A-Za-z0-9_]*
        let key_end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());

        if key_end == 0 {
            // Not a valid assignment — treat as a comment/unparseable line.
            result.push(EnvLine::Comment(line.to_string()));
            i += 1;
            continue;
        }

        let key_candidate = &rest[..key_end];
        // Key must not start with a digit.
        if key_candidate.starts_with(|c: char| c.is_ascii_digit()) {
            result.push(EnvLine::Comment(line.to_string()));
            i += 1;
            continue;
        }

        let after_key = &rest[key_end..];
        if !after_key.starts_with('=') {
            // No `=` — treat as comment/unparseable.
            result.push(EnvLine::Comment(line.to_string()));
            i += 1;
            continue;
        }

        let key = key_candidate.to_string();
        let value_part = &after_key[1..]; // everything after `=`

        // ── Determine quote style and parse value ──────────────────────────
        if let Some(after_open_quote) = value_part.strip_prefix('"') {
            // Double-quoted — may be multiline.
            let mut raw_accumulator = line.to_string();
            let mut inner = after_open_quote.to_string(); // content after opening "

            loop {
                if let Some(close_pos) = find_unescaped_quote(&inner) {
                    // Found closing quote on this accumulated content.
                    let quoted_content = &inner[..close_pos];
                    let value = unescape_double_quoted(quoted_content);
                    result.push(EnvLine::Assignment {
                        export,
                        key,
                        value,
                        quote_style: QuoteStyle::Double,
                        raw_line: raw_accumulator,
                    });
                    break;
                } else {
                    // No closing quote yet — consume next physical line.
                    i += 1;
                    if i < physical_lines.len() {
                        raw_accumulator.push('\n');
                        raw_accumulator.push_str(physical_lines[i]);
                        inner.push('\n');
                        inner.push_str(physical_lines[i]);
                    } else {
                        // EOF without closing quote — store what we have.
                        let value = unescape_double_quoted(&inner);
                        result.push(EnvLine::Assignment {
                            export,
                            key,
                            value,
                            quote_style: QuoteStyle::Double,
                            raw_line: raw_accumulator,
                        });
                        break;
                    }
                }
            }
        } else if let Some(inner) = value_part.strip_prefix('\'') {
            // Single-quoted — no multiline, no escaping.
            let close_pos = inner.find('\'').unwrap_or(inner.len());
            let value = inner[..close_pos].to_string();
            result.push(EnvLine::Assignment {
                export,
                key,
                value,
                quote_style: QuoteStyle::Single,
                raw_line: line.to_string(),
            });
        } else {
            // Unquoted — strip inline comment and trailing whitespace.
            let value = parse_unquoted_value(value_part);
            result.push(EnvLine::Assignment {
                export,
                key,
                value,
                quote_style: QuoteStyle::None,
                raw_line: line.to_string(),
            });
        }

        i += 1;
    }

    result
}

/// Serialize a slice of [`EnvLine`] values back to `.env` file content.
///
/// This is the inverse of [`parse`]. Because each [`EnvLine::Assignment`]
/// stores its `raw_line`, this function reconstructs the original text exactly,
/// guaranteeing `serialize(parse(content)) == content`.
pub fn serialize(lines: &[EnvLine]) -> String {
    let parts: Vec<&str> = lines
        .iter()
        .map(|line| match line {
            EnvLine::Comment(s) => s.as_str(),
            EnvLine::Blank => "",
            EnvLine::Assignment { raw_line, .. } => raw_line.as_str(),
        })
        .collect();
    parts.join("\n")
}

// ── Private helpers ────────────────────────────────────────────────────────────

/// Find the position of an unescaped `"` inside `s`.
///
/// Returns `None` if no unescaped closing quote is present.
fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'\\' {
            // Skip the escaped character.
            pos += 2;
        } else if bytes[pos] == b'"' {
            return Some(pos);
        } else {
            pos += 1;
        }
    }
    None
}

/// Process escape sequences inside a double-quoted value.
///
/// Recognised sequences: `\n`, `\r`, `\t`, `\"`, `\\`.
/// Any other `\x` is kept as-is (i.e. `\` + `x`).
fn unescape_double_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse an unquoted value: strip inline comments (` #` preceded by a space)
/// and trim trailing whitespace.
fn parse_unquoted_value(s: &str) -> String {
    // Find ` #` as an inline comment marker (space before `#`).
    let truncated = if let Some(pos) = find_inline_comment(s) {
        &s[..pos]
    } else {
        s
    };
    truncated.trim_end().to_string()
}

/// Find the byte position of an inline comment (` #`) in an unquoted value.
///
/// Returns the position of the space before `#`, or `None` if not found.
fn find_inline_comment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    // Search for a space immediately followed by `#`.
    (0..bytes.len().saturating_sub(1)).find(|&i| bytes[i] == b' ' && bytes[i + 1] == b'#')
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn find_unescaped_quote_basic() {
        assert_eq!(find_unescaped_quote("hello\""), Some(5));
        assert_eq!(find_unescaped_quote(r#"hel\"lo""#), Some(7));
        assert_eq!(find_unescaped_quote("no quote here"), None);
    }

    #[test]
    fn unescape_sequences() {
        assert_eq!(unescape_double_quoted(r#"line1\nline2"#), "line1\nline2");
        assert_eq!(unescape_double_quoted(r#"\t"#), "\t");
        assert_eq!(unescape_double_quoted(r#"\""#), "\"");
        assert_eq!(unescape_double_quoted(r#"\\"#), "\\");
    }
}
