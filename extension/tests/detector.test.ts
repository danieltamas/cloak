import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { detect, shannonEntropy, SecretType } from '../src/detector';
import { parse } from '../src/envparser';

const TESTDATA = path.resolve(__dirname, '../../testdata');

describe('detector', () => {
    it('detects DatabaseUrl', () => {
        const result = detect('DATABASE_URL', 'postgres://user:pass@host:5432/db');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('DatabaseUrl');
    });

    it('detects StripeKey (sk_live_)', () => {
        const result = detect('STRIPE_KEY', 'sk_test_FAKE4eC39HqLyjWDarjtT1zd');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('StripeKey');
    });

    it('detects StripeKey by key pattern', () => {
        const result = detect('STRIPE_SECRET_KEY', 'some_value_here_long_enough_and_complex');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('StripeKey');
    });

    it('detects AwsAccessKey by value pattern', () => {
        const result = detect('SOME_KEY', 'AKIAIOSFODNN7EXAMPLE');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('AwsAccessKey');
    });

    it('detects AwsAccessKey by key pattern', () => {
        const result = detect('AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7REAL123');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('AwsAccessKey');
    });

    it('detects AwsSecretKey by key pattern', () => {
        const result = detect('AWS_SECRET_ACCESS_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYrealKEY');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('AwsSecretKey');
    });

    it('detects JwtSecret by key pattern', () => {
        const result = detect('JWT_SECRET', 'my-super-secret-jwt-key-that-should-not-leak');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('JwtSecret');
    });

    it('detects ApiKey by value (sk- prefix, len>=40)', () => {
        const result = detect('OPENAI_KEY', 'sk-' + 'a'.repeat(40));
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('ApiKey');
    });

    it('detects PrivateKey by key pattern', () => {
        const result = detect('PRIVATE_KEY', '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('PrivateKey');
    });

    it('detects Password by key pattern', () => {
        const result = detect('DB_PASSWORD', 'supersecretpassword');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Password');
    });

    it('detects Token (ghp_)', () => {
        const result = detect('GITHUB_TOKEN', 'ghp_FAKE0000000000000000000000000000000000');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Token');
    });

    it('detects Token (xoxb- Slack)', () => {
        const result = detect('SLACK_BOT_TOKEN', 'xoxb-0000000000-0000000000000-FAKE00000000000000000000');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Token');
    });

    it('detects Token (eyJ JWT)', () => {
        const result = detect('AUTH_TOKEN', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Token');
    });

    it('does not detect Unknown for short low-entropy value', () => {
        // Unknown requires entropy > 4.5 and length > 20 when no other pattern matches
        const result = detect('SOME_RANDOM_VAR', 'hello');
        expect(result.isSecret).toBe(false);
    });

    it('detects Unknown by high entropy', () => {
        // A mixed-character string with entropy > 4.5 and no specific pattern match
        const result = detect('SOME_HASH', 'aB3xY7mNqR2vZ8wL5kP9cT1uE4sD6jF0gH');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Unknown');
    });

    it('realistic.env: 11 secrets and 6 non-secrets', () => {
        const content = fs.readFileSync(path.join(TESTDATA, 'realistic.env'), 'utf8');
        const lines = parse(content);
        const nonSecretKeys = new Set(['NODE_ENV', 'PORT', 'HOST', 'DEBUG', 'API_BASE_URL', 'FRONTEND_URL']);

        let secretCount = 0;
        let nonSecretCount = 0;

        for (const line of lines) {
            if (line.type !== 'assignment') continue;
            const result = detect(line.key, line.value);
            if (nonSecretKeys.has(line.key)) {
                expect(result.isSecret, `Expected ${line.key} to NOT be a secret`).toBe(false);
                nonSecretCount++;
            } else if (result.isSecret) {
                secretCount++;
            }
        }

        expect(secretCount).toBe(11);
        expect(nonSecretCount).toBe(6);
    });

    it('shannon entropy: empty string returns 0', () => {
        expect(shannonEntropy('')).toBe(0);
    });

    it('shannon entropy: single char returns 0', () => {
        expect(shannonEntropy('a')).toBe(0);
    });

    it('shannon entropy: uniform distribution has max entropy', () => {
        // "abcd" has 4 unique chars, each with prob 0.25 → entropy = 2.0
        const e = shannonEntropy('abcd');
        expect(e).toBeCloseTo(2.0, 5);
    });

    it('shannon entropy: high for random-looking string', () => {
        // Mixed alphanumeric with varied case and digits → entropy > 4.5
        const e = shannonEntropy('aB3xY7mNqR2vZ8wL5kP9cT1uE4sD6jF0gH');
        expect(e).toBeGreaterThan(4.5);
    });

    it('GITHUB_TOKEN with ghp_ value IS detected (value override beats GITHUB_ prefix exclusion)', () => {
        const result = detect('GITHUB_TOKEN', 'ghp_FAKE0000000000000000000000000000000000');
        expect(result.isSecret).toBe(true);
        expect(result.secretType).toBe('Token');
    });

    it('GITHUB_ACTION (GITHUB_ prefix, non-secret value) is NOT detected', () => {
        // A non-secret-pattern value with GITHUB_ prefix should be excluded
        const result = detect('GITHUB_WORKSPACE', '/home/runner/work/myrepo');
        expect(result.isSecret).toBe(false);
    });

    it('trivial values not detected: boolean', () => {
        expect(detect('MY_SECRET', 'true').isSecret).toBe(false);
        expect(detect('MY_SECRET', 'false').isSecret).toBe(false);
        expect(detect('MY_SECRET', 'yes').isSecret).toBe(false);
        expect(detect('MY_SECRET', 'no').isSecret).toBe(false);
    });

    it('trivial values not detected: integer', () => {
        expect(detect('PORT', '3000').isSecret).toBe(false);
        expect(detect('SOME_KEY', '12345').isSecret).toBe(false);
    });

    it('trivial values not detected: localhost', () => {
        expect(detect('HOST', 'localhost').isSecret).toBe(false);
        expect(detect('HOST', '127.0.0.1').isSecret).toBe(false);
    });

    it('trivial values not detected: plain URL without credentials', () => {
        expect(detect('API_URL', 'https://api.example.com/v1').isSecret).toBe(false);
    });

    it('excluded keys not detected', () => {
        expect(detect('NODE_ENV', 'production').isSecret).toBe(false);
        expect(detect('LOG_LEVEL', 'info').isSecret).toBe(false);
        expect(detect('PATH', '/usr/local/bin:/usr/bin').isSecret).toBe(false);
    });

    it('NEXT_PUBLIC_ prefix excluded', () => {
        const result = detect('NEXT_PUBLIC_API_URL', 'https://api.example.com');
        expect(result.isSecret).toBe(false);
    });
});
