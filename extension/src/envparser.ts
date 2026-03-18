/**
 * .env file parser with perfect roundtrip fidelity.
 *
 * Parses .env content into a structured EnvLine representation,
 * preserving the original text so that serialize(parse(content)) === content.
 */

/** How the value portion of an assignment is quoted. */
export type QuoteStyle = 'none' | 'single' | 'double';

/** A key-value assignment. */
export interface Assignment {
    type: 'assignment';
    /** Whether the line began with `export `. */
    exportPrefix: boolean;
    /** The variable name. */
    key: string;
    /** The parsed, unescaped value. */
    value: string;
    /** How the value was quoted in the source. */
    quoteStyle: QuoteStyle;
    /** The original source text (may span multiple physical lines for double-quoted multiline values). */
    rawLine: string;
}

/** A comment line, including any leading whitespace and the `#`. */
export interface Comment {
    type: 'comment';
    content: string;
}

/** A blank (whitespace-only) line. */
export interface Blank {
    type: 'blank';
}

export type EnvLine = Assignment | Comment | Blank;

/**
 * Parse .env content into a list of EnvLine values.
 *
 * Lines are consumed in order. Double-quoted values may span multiple physical lines.
 * The resulting list preserves every byte of the original when round-tripped through serialize.
 */
export function parse(content: string): EnvLine[] {
    const result: EnvLine[] = [];
    const physicalLines = content.split('\n');
    let i = 0;

    while (i < physicalLines.length) {
        const line = physicalLines[i];

        // Blank
        if (line.trim() === '') {
            result.push({ type: 'blank' });
            i++;
            continue;
        }

        // Comment
        if (line.trimStart().startsWith('#')) {
            result.push({ type: 'comment', content: line });
            i++;
            continue;
        }

        // Assignment — optional `export ` prefix
        let exportPrefix = false;
        let rest = line;
        if (line.startsWith('export ')) {
            exportPrefix = true;
            rest = line.slice('export '.length);
        }

        // Key: [A-Za-z_][A-Za-z0-9_]*
        let keyEnd = 0;
        while (keyEnd < rest.length) {
            const c = rest[keyEnd];
            if (!(/[A-Za-z0-9_]/.test(c))) break;
            keyEnd++;
        }

        if (keyEnd === 0) {
            // Not a valid assignment — treat as comment/unparseable
            result.push({ type: 'comment', content: line });
            i++;
            continue;
        }

        const keyCandidate = rest.slice(0, keyEnd);
        // Key must not start with a digit
        if (/^[0-9]/.test(keyCandidate)) {
            result.push({ type: 'comment', content: line });
            i++;
            continue;
        }

        const afterKey = rest.slice(keyEnd);
        if (!afterKey.startsWith('=')) {
            // No `=` — treat as comment/unparseable
            result.push({ type: 'comment', content: line });
            i++;
            continue;
        }

        const key = keyCandidate;
        const valuePart = afterKey.slice(1); // everything after `=`

        // Determine quote style and parse value
        if (valuePart.startsWith('"')) {
            // Double-quoted — may be multiline
            let rawAccumulator = line;
            let inner = valuePart.slice(1); // content after opening "

            // eslint-disable-next-line no-constant-condition
            while (true) {
                const closePos = findUnescapedQuote(inner);
                if (closePos !== null) {
                    // Found closing quote
                    const quotedContent = inner.slice(0, closePos);
                    const value = unescapeDoubleQuoted(quotedContent);
                    result.push({
                        type: 'assignment',
                        exportPrefix,
                        key,
                        value,
                        quoteStyle: 'double',
                        rawLine: rawAccumulator,
                    });
                    break;
                } else {
                    // No closing quote yet — consume next physical line
                    i++;
                    if (i < physicalLines.length) {
                        rawAccumulator += '\n' + physicalLines[i];
                        inner += '\n' + physicalLines[i];
                    } else {
                        // EOF without closing quote — store what we have
                        const value = unescapeDoubleQuoted(inner);
                        result.push({
                            type: 'assignment',
                            exportPrefix,
                            key,
                            value,
                            quoteStyle: 'double',
                            rawLine: rawAccumulator,
                        });
                        break;
                    }
                }
            }
        } else if (valuePart.startsWith("'")) {
            // Single-quoted — no multiline, no escaping
            const inner = valuePart.slice(1);
            const closePos = inner.indexOf("'");
            const value = closePos === -1 ? inner : inner.slice(0, closePos);
            result.push({
                type: 'assignment',
                exportPrefix,
                key,
                value,
                quoteStyle: 'single',
                rawLine: line,
            });
        } else {
            // Unquoted — strip inline comment and trailing whitespace
            const value = parseUnquotedValue(valuePart);
            result.push({
                type: 'assignment',
                exportPrefix,
                key,
                value,
                quoteStyle: 'none',
                rawLine: line,
            });
        }

        i++;
    }

    return result;
}

/**
 * Serialize a list of EnvLine values back to .env file content.
 *
 * This is the inverse of parse. Because each Assignment stores its rawLine,
 * this function reconstructs the original text exactly,
 * guaranteeing serialize(parse(content)) === content.
 */
export function serialize(lines: EnvLine[]): string {
    return lines
        .map(line => {
            if (line.type === 'comment') return line.content;
            if (line.type === 'blank') return '';
            return line.rawLine; // assignment
        })
        .join('\n');
}

// ── Private helpers ──────────────────────────────────────────────────────────

/**
 * Find the position of an unescaped `"` inside s.
 * Returns null if no unescaped closing quote is present.
 */
function findUnescapedQuote(s: string): number | null {
    let pos = 0;
    while (pos < s.length) {
        if (s[pos] === '\\') {
            // Skip the escaped character
            pos += 2;
        } else if (s[pos] === '"') {
            return pos;
        } else {
            pos++;
        }
    }
    return null;
}

/**
 * Process escape sequences inside a double-quoted value.
 * Recognised sequences: \n, \r, \t, \", \\.
 * Any other \x is kept as-is (i.e. \ + x).
 */
function unescapeDoubleQuoted(s: string): string {
    let result = '';
    let i = 0;
    while (i < s.length) {
        if (s[i] === '\\') {
            i++;
            if (i >= s.length) {
                result += '\\';
                break;
            }
            switch (s[i]) {
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default:
                    result += '\\';
                    result += s[i];
            }
        } else {
            result += s[i];
        }
        i++;
    }
    return result;
}

/**
 * Parse an unquoted value: strip inline comments (` #` preceded by a space)
 * and trim trailing whitespace.
 */
function parseUnquotedValue(s: string): string {
    const commentPos = findInlineComment(s);
    const truncated = commentPos !== null ? s.slice(0, commentPos) : s;
    return truncated.trimEnd();
}

/**
 * Find the byte position of an inline comment (` #`) in an unquoted value.
 * Returns the position of the space before `#`, or null if not found.
 */
function findInlineComment(s: string): number | null {
    for (let i = 0; i < s.length - 1; i++) {
        if (s[i] === ' ' && s[i + 1] === '#') {
            return i;
        }
    }
    return null;
}
