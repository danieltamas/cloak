//! Integration tests for `cli/src/envparser.rs`.
//!
//! Run with: `cd cli && cargo test --test envparser_test -- --nocapture`

use cloak::envparser::{parse, serialize, EnvLine, QuoteStyle};

// ── 1. parse_simple_assignment ────────────────────────────────────────────────
#[test]
fn parse_simple_assignment() {
    let lines = parse("KEY=value");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment {
            export,
            key,
            value,
            quote_style,
            raw_line,
        } => {
            assert!(!export);
            assert_eq!(key, "KEY");
            assert_eq!(value, "value");
            assert_eq!(*quote_style, QuoteStyle::None);
            assert_eq!(raw_line, "KEY=value");
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 2. parse_double_quoted ────────────────────────────────────────────────────
#[test]
fn parse_double_quoted() {
    let lines = parse(r#"KEY="value with spaces""#);
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment {
            key,
            value,
            quote_style,
            ..
        } => {
            assert_eq!(key, "KEY");
            assert_eq!(value, "value with spaces");
            assert_eq!(*quote_style, QuoteStyle::Double);
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 3. parse_single_quoted ────────────────────────────────────────────────────
#[test]
fn parse_single_quoted() {
    let lines = parse("KEY='value'");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment {
            key,
            value,
            quote_style,
            ..
        } => {
            assert_eq!(key, "KEY");
            assert_eq!(value, "value");
            assert_eq!(*quote_style, QuoteStyle::Single);
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 4. parse_unquoted_with_inline_comment ─────────────────────────────────────
#[test]
fn parse_unquoted_with_inline_comment() {
    let lines = parse("KEY=value # comment");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment { key, value, .. } => {
            assert_eq!(key, "KEY");
            assert_eq!(value, "value");
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 5. parse_comment_line ─────────────────────────────────────────────────────
#[test]
fn parse_comment_line() {
    let lines = parse("# this is a comment");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Comment(s) => assert_eq!(s, "# this is a comment"),
        other => panic!("expected Comment, got {:?}", other),
    }
}

// ── 6. parse_blank_line ───────────────────────────────────────────────────────
#[test]
fn parse_blank_line() {
    let lines = parse("");
    // A single empty string split on '\n' gives one blank line.
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], EnvLine::Blank);
}

// ── 7. parse_export_prefix ───────────────────────────────────────────────────
#[test]
fn parse_export_prefix() {
    let lines = parse("export KEY=value");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment {
            export, key, value, ..
        } => {
            assert!(*export);
            assert_eq!(key, "KEY");
            assert_eq!(value, "value");
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 8. parse_escaped_chars ────────────────────────────────────────────────────
#[test]
fn parse_escaped_chars() {
    // Raw source: KEY="line1\nline2\ttab\"quote\\back"
    let source = r#"KEY="line1\nline2\ttab\"quote\\back""#;
    let lines = parse(source);
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment {
            value,
            quote_style,
            raw_line,
            ..
        } => {
            assert_eq!(*quote_style, QuoteStyle::Double);
            assert_eq!(value, "line1\nline2\ttab\"quote\\back");
            assert_eq!(raw_line, source);
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}

// ── 9. parse_multiline_double_quoted ─────────────────────────────────────────
#[test]
fn parse_multiline_double_quoted() {
    // Load the PRIVATE_KEY from edge-cases.env.
    let content = std::fs::read_to_string("../testdata/edge-cases.env").unwrap();
    let lines = parse(&content);

    // Find the PRIVATE_KEY assignment.
    let pk = lines
        .iter()
        .find(|l| matches!(l, EnvLine::Assignment { key, .. } if key == "PRIVATE_KEY"));
    assert!(pk.is_some(), "PRIVATE_KEY not found");

    match pk.unwrap() {
        EnvLine::Assignment {
            key,
            value,
            quote_style,
            raw_line,
            ..
        } => {
            assert_eq!(key, "PRIVATE_KEY");
            assert_eq!(*quote_style, QuoteStyle::Double);
            // Value should contain the newline from the multiline block.
            assert!(value.contains("-----BEGIN RSA PRIVATE KEY-----"));
            assert!(value.contains("-----END RSA PRIVATE KEY-----"));
            // raw_line should span the three physical lines.
            assert!(raw_line.contains('\n'));
        }
        _ => unreachable!(),
    }
}

// ── 10. roundtrip_realistic_env ───────────────────────────────────────────────
#[test]
fn roundtrip_realistic_env() {
    let content = std::fs::read_to_string("../testdata/realistic.env").unwrap();
    let lines = parse(&content);
    let output = serialize(&lines);
    assert_eq!(output, content);
}

// ── 11. roundtrip_edge_cases_env ─────────────────────────────────────────────
#[test]
fn roundtrip_edge_cases_env() {
    let content = std::fs::read_to_string("../testdata/edge-cases.env").unwrap();
    let lines = parse(&content);
    let output = serialize(&lines);
    assert_eq!(output, content);
}

// ── 12. parse_duplicate_keys ─────────────────────────────────────────────────
#[test]
fn parse_duplicate_keys() {
    let input = "DUPE_KEY=first\nDUPE_KEY=second";
    let lines = parse(input);
    assert_eq!(lines.len(), 2);

    let values: Vec<&str> = lines
        .iter()
        .filter_map(|l| match l {
            EnvLine::Assignment { key, value, .. } if key == "DUPE_KEY" => Some(value.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(values, vec!["first", "second"]);
}

// ── 13. parse_empty_value ─────────────────────────────────────────────────────
#[test]
fn parse_empty_value() {
    let lines = parse("KEY=");
    assert_eq!(lines.len(), 1);
    match &lines[0] {
        EnvLine::Assignment { key, value, .. } => {
            assert_eq!(key, "KEY");
            assert_eq!(value, "");
        }
        other => panic!("expected Assignment, got {:?}", other),
    }
}
