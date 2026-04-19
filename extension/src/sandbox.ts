/**
 * Sandbox value generation for Cloak.
 *
 * Generates fake but structurally valid replacement values for detected secrets.
 * Sandbox values are deterministic: the same (key, value, SecretType, projectHash)
 * inputs always produce the same output. This allows .env files on disk to contain
 * consistent fake credentials that look plausible but are never real.
 */

import crypto from 'crypto';
import { SecretType } from './detector';
import { parse, serialize, EnvLine, QuoteStyle } from './envparser';
import { detect } from './detector';

/**
 * Generate a deterministic hex string from SHA-256("cloak-sandbox:<projectHash>:<key>"),
 * truncated to `length` hex characters (each hex char = 4 bits).
 *
 * Always returns at most 64 characters (the full SHA-256 hex output).
 */
export function deterministicHex(projectHash: string, key: string, length: number): string {
    const input = `cloak-sandbox:${projectHash}:${key}`;
    const hash = crypto.createHash('sha256').update(input, 'utf8').digest('hex');
    return hash.slice(0, Math.min(length, hash.length));
}

/**
 * Generate a sandbox (fake) value for a detected secret.
 *
 * The returned value is structurally valid for the given secretType but
 * contains no real credentials. Stripe test keys (sk_test_*, pk_test_*)
 * are passed through unchanged so that test environments continue to work.
 */
export function sandboxValue(
    key: string,
    value: string,
    secretType: SecretType,
    projectHash: string,
): string {
    switch (secretType) {
        case 'DatabaseUrl':
            if (value.startsWith('postgres://')) {
                return 'postgres://dev:dev@localhost:5432/devdb';
            } else if (value.startsWith('mysql://')) {
                return 'mysql://dev:dev@localhost:3306/devdb';
            } else if (value.startsWith('mongodb://')) {
                return 'mongodb://localhost:27017/devdb';
            } else if (value.startsWith('redis://')) {
                return 'redis://localhost:6379';
            } else {
                return 'postgres://dev:dev@localhost:5432/devdb';
            }

        case 'StripeKey':
            // Test keys pass through unchanged
            if (value.startsWith('sk_test_') || value.startsWith('pk_test_')) {
                return value;
            }
            if (value.startsWith('sk_live_') || value.startsWith('sk_')) {
                return 'sk_test_cloak_sandbox_000000000000';
            } else if (value.startsWith('pk_live_') || value.startsWith('pk_')) {
                return 'pk_test_cloak_sandbox_000000000000';
            } else {
                return `sk_test_cloak_sandbox_${deterministicHex(projectHash, key, 12)}`;
            }

        case 'AwsAccessKey':
            return 'AKIAIOSFODNN7EXAMPLE';

        case 'AwsSecretKey':
            return 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

        case 'JwtSecret':
            return 'cloak-dev-jwt-secret-not-real-000000';

        case 'ApiKey':
            if (value.startsWith('sk-')) {
                return `sk-cloak-sandbox-key-${deterministicHex(projectHash, key, 20)}`;
            } else {
                return `cloak_sandbox_api_key_${deterministicHex(projectHash, key, 20)}`;
            }

        case 'PrivateKey':
            return 'cloak-sandbox-private-key-not-real';

        case 'Password':
            return 'cloak_sandbox_password';

        case 'Token':
            if (value.startsWith('ghp_')) {
                return `ghp_cloaksandbox${deterministicHex(projectHash, key, 20)}`;
            } else if (value.startsWith('xoxb-')) {
                // Split literal to avoid secretlint false-positive during `vsce`/`ovsx` publish.
                return 'xoxb' + '-0000-0000-cloaksandboxtoken';
            } else if (value.startsWith('eyJ')) {
                return 'eyJjbG9hayI6InNhbmRib3gifQ==';
            } else {
                return `cloak_sandbox_token_${deterministicHex(projectHash, key, 20)}`;
            }

        case 'GenericUrl':
            return replaceUrlCredentials(value);

        case 'Unknown':
            return `cloak_sandbox_${deterministicHex(projectHash, key, 20)}`;
    }
}

/**
 * Replace credentials in a URL with `dev:dev@<host>`, preserving scheme,
 * host, port, path, query, and fragment.
 *
 * If the value does not contain `://`, returns the value unchanged.
 */
function replaceUrlCredentials(value: string): string {
    const schemeEnd = value.indexOf('://');
    if (schemeEnd === -1) {
        return value;
    }
    const scheme = value.slice(0, schemeEnd);
    const afterScheme = value.slice(schemeEnd + 3);

    // Split authority from path (first '/')
    const slashPos = afterScheme.indexOf('/');
    let authority: string;
    let pathAndRest: string;
    if (slashPos !== -1) {
        authority = afterScheme.slice(0, slashPos);
        pathAndRest = afterScheme.slice(slashPos);
    } else {
        authority = afterScheme;
        pathAndRest = '';
    }

    // Strip any existing userinfo (everything up to and including the last '@')
    const atPos = authority.lastIndexOf('@');
    const hostPort = atPos !== -1 ? authority.slice(atPos + 1) : authority;

    return `${scheme}://dev:dev@${hostPort}${pathAndRest}`;
}

/**
 * Process a full .env file content: parse lines, detect secrets, replace
 * detected secret values with their sandbox equivalents, and serialize back.
 *
 * Preserves all comments, blank lines, ordering, quote style, and `export`
 * prefix. Non-secret assignments are left completely unchanged (including
 * their original rawLine).
 */
export function sandboxEnv(content: string, projectHash: string): string {
    const lines = parse(content);

    for (const line of lines) {
        if (line.type !== 'assignment') continue;

        const detection = detect(line.key, line.value);
        if (detection.isSecret && detection.secretType !== null) {
            const newValue = sandboxValue(line.key, line.value, detection.secretType, projectHash);
            const exportPrefix = line.exportPrefix ? 'export ' : '';
            let newRaw: string;
            switch (line.quoteStyle) {
                case 'double':
                    newRaw = `${exportPrefix}${line.key}="${newValue}"`;
                    break;
                case 'single':
                    newRaw = `${exportPrefix}${line.key}='${newValue}'`;
                    break;
                case 'none':
                default:
                    newRaw = `${exportPrefix}${line.key}=${newValue}`;
                    break;
            }
            line.value = newValue;
            line.rawLine = newRaw;
        }
    }

    return serialize(lines);
}
