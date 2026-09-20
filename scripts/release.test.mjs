import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const names = ['Tachyon_0.2.1_aarch64.dmg', 'Tachyon_0.2.1_amd64.deb', 'Tachyon_0.2.1_amd64.AppImage'];
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tachyon-release-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'installers');
  const output = path.join(root, 'release-assets');
  fs.mkdirSync(source);
  const run = () => spawnSync(process.execPath, [new URL('./release.mjs', import.meta.url).pathname, 'v0.2.1', source, output], { encoding: 'utf8' });
  return { source, output, run };
}

test('complete platform set produces verifiable checksums and versioned notes', t => {
  const { source, output, run } = fixture(t);
  for (const name of names) fs.writeFileSync(path.join(source, name), `installer ${name}`);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const checksums = fs.readFileSync(path.join(output, 'SHA256SUMS'), 'utf8').trim().split('\n');
  assert.equal(checksums.length, names.length);
  for (const name of names) {
    const digest = createHash('sha256').update(fs.readFileSync(path.join(output, name))).digest('hex');
    assert.ok(checksums.includes(`${digest}  ${name}`));
  }
  assert.match(fs.readFileSync(path.join(output, 'RELEASE_NOTES.md'), 'utf8'), /blob\/v0\.2\.1\/CHANGELOG/);
});

test('missing, empty and duplicate installers block publication', t => {
  const { source, run } = fixture(t);
  assert.notEqual(run().status, 0);
  for (const name of names) fs.writeFileSync(path.join(source, name), 'installer');
  fs.writeFileSync(path.join(source, names[2]), '');
  assert.match(run().stderr, /Empty installer/);
  fs.writeFileSync(path.join(source, names[2]), 'installer');
  fs.mkdirSync(path.join(source, 'duplicate'));
  fs.copyFileSync(path.join(source, names[0]), path.join(source, 'duplicate', names[0]));
  assert.match(run().stderr, /Expected exactly one/);
});
