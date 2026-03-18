import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { parse, serialize, EnvLine } from '../src/envparser';

const TESTDATA = path.resolve(__dirname, '../../testdata');

describe('envparser', () => {
    it('roundtrip: realistic.env', () => {
        const content = fs.readFileSync(path.join(TESTDATA, 'realistic.env'), 'utf8');
        expect(serialize(parse(content))).toBe(content);
    });

    it('roundtrip: edge-cases.env', () => {
        const content = fs.readFileSync(path.join(TESTDATA, 'edge-cases.env'), 'utf8');
        expect(serialize(parse(content))).toBe(content);
    });

    it('basic parsing: simple KEY=value, comments, blanks', () => {
        const content = '# comment\nKEY=value\n\nFOO=bar';
        const lines = parse(content);
        expect(lines).toHaveLength(4);
        expect(lines[0]).toEqual({ type: 'comment', content: '# comment' });
        expect(lines[1]).toMatchObject({ type: 'assignment', key: 'KEY', value: 'value', quoteStyle: 'none' });
        expect(lines[2]).toEqual({ type: 'blank' });
        expect(lines[3]).toMatchObject({ type: 'assignment', key: 'FOO', value: 'bar', quoteStyle: 'none' });
    });

    it('double-quoted multiline values', () => {
        const content = 'KEY="line1\nline2"';
        const lines = parse(content);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({
            type: 'assignment',
            key: 'KEY',
            value: 'line1\nline2',
            quoteStyle: 'double',
            rawLine: 'KEY="line1\nline2"',
        });
    });

    it('double-quoted multiline roundtrip', () => {
        const content = 'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"';
        expect(serialize(parse(content))).toBe(content);
    });

    it('single-quoted values (no escaping)', () => {
        const content = "KEY='hello\\nworld'";
        const lines = parse(content);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({
            type: 'assignment',
            key: 'KEY',
            value: 'hello\\nworld', // no escape processing
            quoteStyle: 'single',
        });
    });

    it('export prefix handling', () => {
        const content = 'export MY_SECRET=abc123';
        const lines = parse(content);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({
            type: 'assignment',
            key: 'MY_SECRET',
            exportPrefix: true,
            value: 'abc123',
            quoteStyle: 'none',
            rawLine: 'export MY_SECRET=abc123',
        });
    });

    it('unquoted value with inline comment', () => {
        const content = 'KEY=myvalue # this is a comment';
        const lines = parse(content);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({
            type: 'assignment',
            key: 'KEY',
            value: 'myvalue',
            quoteStyle: 'none',
        });
    });

    it('double-quoted value with escape sequences', () => {
        const content = 'KEY="line1\\nline2\\ttab"';
        const lines = parse(content);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatchObject({
            type: 'assignment',
            key: 'KEY',
            value: 'line1\nline2\ttab',
            quoteStyle: 'double',
        });
    });

    it('invalid lines treated as comments', () => {
        const content = '123INVALID=value\n=nokey';
        const lines = parse(content);
        expect(lines[0]).toMatchObject({ type: 'comment', content: '123INVALID=value' });
        expect(lines[1]).toMatchObject({ type: 'comment', content: '=nokey' });
    });
});
