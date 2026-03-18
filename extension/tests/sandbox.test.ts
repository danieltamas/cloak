import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { deterministicHex, sandboxValue, sandboxEnv } from '../src/sandbox';
import { parse } from '../src/envparser';
import { detect } from '../src/detector';

const TESTDATA = path.resolve(__dirname, '../../testdata');

describe('sandbox', () => {
    it('deterministicHex produces correct length', () => {
        const h = deterministicHex('proj123', 'MY_KEY', 20);
        expect(h.length).toBe(20);
        expect(h).toMatch(/^[0-9a-f]+$/);
    });

    it('deterministicHex produces correct length when requesting short hex', () => {
        const h = deterministicHex('proj123', 'MY_KEY', 12);
        expect(h.length).toBe(12);
    });

    it('deterministicHex is deterministic (same inputs → same output)', () => {
        const h1 = deterministicHex('proj', 'key', 16);
        const h2 = deterministicHex('proj', 'key', 16);
        expect(h1).toBe(h2);
    });

    it('deterministicHex differs by project hash', () => {
        const h1 = deterministicHex('hash_a', 'key', 16);
        const h2 = deterministicHex('hash_b', 'key', 16);
        expect(h1).not.toBe(h2);
    });

    it('deterministicHex differs by key', () => {
        const h1 = deterministicHex('proj', 'KEY_A', 16);
        const h2 = deterministicHex('proj', 'KEY_B', 16);
        expect(h1).not.toBe(h2);
    });

    it('Stripe test key passthrough (sk_test_ → unchanged)', () => {
        const result = sandboxValue('STRIPE_KEY', 'sk_test_xxx123', 'StripeKey', 'proj');
        expect(result).toBe('sk_test_xxx123');
    });

    it('Stripe test key passthrough (pk_test_ → unchanged)', () => {
        const result = sandboxValue('STRIPE_PK', 'pk_test_yyy456', 'StripeKey', 'proj');
        expect(result).toBe('pk_test_yyy456');
    });

    it('Stripe live sk_ key → sk_test_cloak_sandbox_000000000000', () => {
        const result = sandboxValue('STRIPE_SK', 'sk_test_FAKE4eC39HqLyjWDarjtT1zd', 'StripeKey', 'proj');
        expect(result).toBe('sk_test_cloak_sandbox_000000000000');
    });

    it('Stripe live pk_ key → pk_test_cloak_sandbox_000000000000', () => {
        const result = sandboxValue('STRIPE_PK', 'pk_test_FAKEoMQauvdEDq54NiTphI7jx', 'StripeKey', 'proj');
        expect(result).toBe('pk_test_cloak_sandbox_000000000000');
    });

    it('database URL sandbox values: postgres', () => {
        const result = sandboxValue('DATABASE_URL', 'postgres://admin:s3cret@db.prod.com:5432/myapp', 'DatabaseUrl', 'proj');
        expect(result).toBe('postgres://dev:dev@localhost:5432/devdb');
    });

    it('database URL sandbox values: mysql', () => {
        const result = sandboxValue('DB_URL', 'mysql://user:pass@host:3306/mydb', 'DatabaseUrl', 'proj');
        expect(result).toBe('mysql://dev:dev@localhost:3306/devdb');
    });

    it('database URL sandbox values: mongodb', () => {
        const result = sandboxValue('MONGO_URI', 'mongodb://user:pass@host:27017/db', 'DatabaseUrl', 'proj');
        expect(result).toBe('mongodb://localhost:27017/devdb');
    });

    it('database URL sandbox values: redis', () => {
        const result = sandboxValue('REDIS_URL', 'redis://:pass@cache.prod.com:6379/0', 'DatabaseUrl', 'proj');
        expect(result).toBe('redis://localhost:6379');
    });

    it('AWS access key → AKIAIOSFODNN7EXAMPLE', () => {
        const result = sandboxValue('AWS_ACCESS_KEY_ID', 'AKIAIOSFODNN7REAL123', 'AwsAccessKey', 'proj');
        expect(result).toBe('AKIAIOSFODNN7EXAMPLE');
    });

    it('AWS secret key → standard example key', () => {
        const result = sandboxValue('AWS_SECRET_ACCESS_KEY', 'real-secret', 'AwsSecretKey', 'proj');
        expect(result).toBe('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    });

    it('JWT secret → cloak-dev-jwt-secret-not-real-000000', () => {
        const result = sandboxValue('JWT_SECRET', 'real-jwt-secret', 'JwtSecret', 'proj');
        expect(result).toBe('cloak-dev-jwt-secret-not-real-000000');
    });

    it('ApiKey (sk- prefix) → sk-cloak-sandbox-key-{hex20}', () => {
        const result = sandboxValue('OPENAI_KEY', 'sk-' + 'a'.repeat(40), 'ApiKey', 'proj');
        expect(result).toMatch(/^sk-cloak-sandbox-key-[0-9a-f]{20}$/);
    });

    it('ApiKey (non-sk) → cloak_sandbox_api_key_{hex20}', () => {
        const result = sandboxValue('API_KEY', 'SG.xxxxx.yyyyyyy', 'ApiKey', 'proj');
        expect(result).toMatch(/^cloak_sandbox_api_key_[0-9a-f]{20}$/);
    });

    it('PrivateKey → cloak-sandbox-private-key-not-real', () => {
        const result = sandboxValue('PRIVATE_KEY', '-----BEGIN RSA PRIVATE KEY-----', 'PrivateKey', 'proj');
        expect(result).toBe('cloak-sandbox-private-key-not-real');
    });

    it('Password → cloak_sandbox_password', () => {
        const result = sandboxValue('DB_PASSWORD', 'real_password', 'Password', 'proj');
        expect(result).toBe('cloak_sandbox_password');
    });

    it('Token (ghp_) → ghp_cloaksandbox{hex20}', () => {
        const result = sandboxValue('GITHUB_TOKEN', 'ghp_FAKE0000000000000000000000000000000000', 'Token', 'proj');
        expect(result).toMatch(/^ghp_cloaksandbox[0-9a-f]{20}$/);
    });

    it('Token (xoxb-) → xoxb-0000-0000-cloaksandboxtoken', () => {
        const result = sandboxValue('SLACK_TOKEN', 'xoxb-123-456-abc', 'Token', 'proj');
        expect(result).toBe('xoxb-0000-0000-cloaksandboxtoken');
    });

    it('Token (eyJ JWT) → eyJjbG9hayI6InNhbmRib3gifQ==', () => {
        const result = sandboxValue('AUTH_TOKEN', 'eyJhbGciOiJIUzI1NiJ9.xxx.yyy', 'Token', 'proj');
        expect(result).toBe('eyJjbG9hayI6InNhbmRib3gifQ==');
    });

    it('Token (generic) → cloak_sandbox_token_{hex20}', () => {
        const result = sandboxValue('SESSION_TOKEN', 'some-session-token-value', 'Token', 'proj');
        expect(result).toMatch(/^cloak_sandbox_token_[0-9a-f]{20}$/);
    });

    it('Unknown → cloak_sandbox_{hex20}', () => {
        const result = sandboxValue('MYSTERY', 'highentropy123', 'Unknown', 'proj');
        expect(result).toMatch(/^cloak_sandbox_[0-9a-f]{20}$/);
    });

    it('GenericUrl → replaces credentials with dev:dev@', () => {
        const result = sandboxValue('SOME_URL', 'https://user:pass@example.com/path', 'GenericUrl', 'proj');
        expect(result).toBe('https://dev:dev@example.com/path');
    });

    it('sandboxEnv preserves non-secrets', () => {
        const content = 'NODE_ENV=production\nPORT=3000\nDEBUG=false\n';
        const result = sandboxEnv(content, 'proj123');
        expect(result).toBe(content);
    });

    it('sandboxEnv replaces DATABASE_URL', () => {
        const content = 'DATABASE_URL=postgres://admin:s3cret@db.prod.com:5432/myapp\nNODE_ENV=production\n';
        const result = sandboxEnv(content, 'proj123');
        expect(result).toContain('DATABASE_URL=postgres://dev:dev@localhost:5432/devdb');
        expect(result).toContain('NODE_ENV=production');
    });

    it('sandboxEnv preserves comments and blank lines', () => {
        const content = '# This is a comment\n\nDB_PASSWORD=secret123\n';
        const result = sandboxEnv(content, 'proj123');
        expect(result).toContain('# This is a comment');
        expect(result).toContain('\n\n');
        expect(result).toContain('DB_PASSWORD=cloak_sandbox_password');
    });

    it('sandboxEnv uses consistent sandbox values (deterministic)', () => {
        const content = 'MY_SECRET=aB3xY7mNqR2vZ8wL5kP9cT1uE4sD6jF0gH\n';
        const result1 = sandboxEnv(content, 'myhash');
        const result2 = sandboxEnv(content, 'myhash');
        expect(result1).toBe(result2);
    });

    it('sandboxEnv: different project hashes produce different Unknown sandbox values', () => {
        const content = 'SOME_HASH=aB3xY7mNqR2vZ8wL5kP9cT1uE4sD6jF0gH\n';
        const result1 = sandboxEnv(content, 'hash_a');
        const result2 = sandboxEnv(content, 'hash_b');
        expect(result1).not.toBe(result2);
    });
});
