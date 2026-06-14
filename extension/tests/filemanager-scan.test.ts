/**
 * Tests for the extension's recursive .env discovery (findEnvFilesWithSecrets),
 * mirroring the CLI's `scan_env_files` behavior: nested files are found, vendored
 * and build directories are skipped, no-secret files are excluded, depth is capped.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { findEnvFilesWithSecrets } from '../src/filemanager';

/** A .env line the detector reliably flags as a secret. */
const SECRET_LINE = 'DATABASE_URL=postgres://user:password@localhost:5432/db\n';

describe('findEnvFilesWithSecrets', () => {
    let root: string;

    beforeEach(async () => {
        root = await fs.mkdtemp(path.join(os.tmpdir(), 'cloak-scan-'));
    });

    afterEach(async () => {
        await fs.rm(root, { recursive: true, force: true });
    });

    it('finds nested .env files with secrets', async () => {
        await fs.writeFile(path.join(root, '.env'), SECRET_LINE);
        await fs.mkdir(path.join(root, 'apps', 'api'), { recursive: true });
        await fs.writeFile(path.join(root, 'apps', 'api', '.env'), SECRET_LINE);

        const found = (await findEnvFilesWithSecrets(root)).map(f => f.relPath);
        expect(found).toContain('.env');
        expect(found).toContain('apps/api/.env');
    });

    it('skips node_modules, build output, and dot-directories', async () => {
        await fs.writeFile(path.join(root, '.env'), SECRET_LINE);
        for (const dir of ['node_modules/pkg', 'dist', '.hidden']) {
            await fs.mkdir(path.join(root, dir), { recursive: true });
            await fs.writeFile(path.join(root, dir, '.env'), SECRET_LINE);
        }

        const found = (await findEnvFilesWithSecrets(root)).map(f => f.relPath);
        expect(found).toEqual(['.env']);
    });

    it('excludes .env files without secrets', async () => {
        await fs.writeFile(path.join(root, '.env'), SECRET_LINE);
        await fs.mkdir(path.join(root, 'config'), { recursive: true });
        await fs.writeFile(path.join(root, 'config', '.env'), 'PORT=3000\nNODE_ENV=production\n');

        const found = (await findEnvFilesWithSecrets(root)).map(f => f.relPath);
        expect(found).toEqual(['.env']);
    });

    it('reports the secret count per file', async () => {
        await fs.writeFile(path.join(root, '.env'), SECRET_LINE + 'API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789\n');
        const found = await findEnvFilesWithSecrets(root);
        expect(found).toHaveLength(1);
        expect(found[0].secretCount).toBeGreaterThanOrEqual(2);
    });

    it('does not descend into independently-protected sub-projects', async () => {
        await fs.writeFile(path.join(root, '.env'), SECRET_LINE);
        // A sub-project with its own .cloak marker.
        await fs.mkdir(path.join(root, 'service'), { recursive: true });
        await fs.writeFile(path.join(root, 'service', '.cloak'), '{}');
        await fs.writeFile(path.join(root, 'service', '.env'), SECRET_LINE);

        const found = (await findEnvFilesWithSecrets(root)).map(f => f.relPath);
        expect(found).toEqual(['.env']);
    });

    it('respects the depth cap', async () => {
        let deep = root;
        for (let i = 0; i < 7; i++) deep = path.join(deep, 'd');
        await fs.mkdir(deep, { recursive: true });
        await fs.writeFile(path.join(deep, '.env'), SECRET_LINE);

        const found = await findEnvFilesWithSecrets(root);
        expect(found).toEqual([]);
    });
});
