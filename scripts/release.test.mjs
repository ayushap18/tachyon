import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const names = ['Tachyon_0.2.1_aarch64.dmg', 'Tachyon_0.2.1_amd64.deb', 'Tachyon_0.2.1_amd64.AppImage'];
// What a signed CI run adds: the macOS updater tarball plus a .sig for each updater download.
const signedNames = ['Tachyon.app.tar.gz', 'Tachyon.app.tar.gz.sig', 'Tachyon_0.2.1_amd64.AppImage.sig'];
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tachyon-release-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'installers');
  const output = path.join(root, 'release-assets');
  fs.mkdirSync(source);
  const run = (signed = false) => spawnSync(process.execPath, [new URL('./release.mjs', import.meta.url).pathname, 'v0.2.1', source, output],
    { encoding: 'utf8', env: { ...process.env, UPDATER_SIGNED: String(signed) } });
  return { source, output, run };
}

// What tools/sign-updater writes: base64 of a minisign box whose trusted comment records the
// version. release.mjs refuses a signed build whose .sig files lack it.
const sigFor = (name, version = '0.2.1') =>
  Buffer.from(`untrusted comment: signature from tauri secret key\nRUTest\ntrusted comment: timestamp:1\tfile:${name}\tversion:${version}\nsig\n`).toString('base64');
const content = name => (name.endsWith('.sig') ? sigFor(name.slice(0, -4)) : `file ${name}\n`);

test('complete platform set produces verifiable checksums, versioned notes and latest.json', t => {
  const { source, output, run } = fixture(t);
  for (const name of [...names, ...signedNames]) fs.writeFileSync(path.join(source, name), content(name));
  const result = run(true);
  assert.equal(result.status, 0, result.stderr);
  const checksums = fs.readFileSync(path.join(output, 'SHA256SUMS'), 'utf8').trim().split('\n');
  assert.equal(checksums.length, names.length + signedNames.length);
  for (const name of [...names, ...signedNames]) {
    const digest = createHash('sha256').update(fs.readFileSync(path.join(output, name))).digest('hex');
    assert.ok(checksums.includes(`${digest}  ${name}`));
  }
  const notes = fs.readFileSync(path.join(output, 'RELEASE_NOTES.md'), 'utf8');
  assert.match(notes, /blob\/v0\.2\.1\/CHANGELOG/);
  // Which artifact can replace itself is the question every user of the notes has.
  assert.match(notes, /\.dmg` \| In place: ⌘U/);
  assert.match(notes, /\.deb` \| No: install the new \.deb with apt/);
  assert.match(notes, /\.AppImage` \| In place: Ctrl\+U/);
  assert.match(notes, /first install/);
  assert.doesNotMatch(notes, /no updater manifest/);
  const latest = JSON.parse(fs.readFileSync(path.join(output, 'latest.json'), 'utf8'));
  assert.equal(latest.version, '0.2.1');
  assert.deepEqual(Object.keys(latest.platforms).sort(), ['darwin-aarch64', 'linux-x86_64']);
  for (const { url, signature } of Object.values(latest.platforms)) {
    assert.ok(url.startsWith('https://github.com/ayushap18/tachyon/releases/download/v0.2.1/'), url);
    assert.ok(signature.length > 0);
  }
  assert.equal(latest.platforms['darwin-aarch64'].signature, sigFor('Tachyon.app.tar.gz'));
});

// No signing secrets yet: the release still ships, the updater simply is not offered it.
test('unsigned build publishes installers without latest.json and says so', t => {
  const { source, output, run } = fixture(t);
  for (const name of names) fs.writeFileSync(path.join(source, name), `installer ${name}`);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!fs.existsSync(path.join(output, 'latest.json')));
  assert.equal(fs.readFileSync(path.join(output, 'SHA256SUMS'), 'utf8').trim().split('\n').length, names.length);
  assert.match(fs.readFileSync(path.join(output, 'RELEASE_NOTES.md'), 'utf8'), /no updater manifest/);
});

test('missing, empty and duplicate installers block publication', t => {
  const { source, run } = fixture(t);
  assert.notEqual(run().status, 0);
  for (const name of names) fs.writeFileSync(path.join(source, name), 'installer');
  fs.writeFileSync(path.join(source, names[2]), '');
  assert.match(run().stderr, /Empty release file/);
  fs.writeFileSync(path.join(source, names[2]), 'installer');
  fs.mkdirSync(path.join(source, 'duplicate'));
  fs.copyFileSync(path.join(source, names[0]), path.join(source, 'duplicate', names[0]));
  assert.match(run().stderr, /Expected exactly one/);
});

test('a signed build missing one .sig blocks publication', t => {
  const { source, output, run } = fixture(t);
  for (const name of [...names, ...signedNames]) fs.writeFileSync(path.join(source, name), content(name));
  fs.rmSync(path.join(source, 'Tachyon_0.2.1_amd64.AppImage.sig'));
  const result = run(true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Expected exactly one Tachyon_0\.2\.1_amd64\.AppImage\.sig/);
  assert.ok(!fs.existsSync(path.join(output, 'latest.json')));
});

// README hardcodes installer filenames, which carry the version; it drifted 3 releases behind
// the manifests before anything noticed. tauri.conf.json is the name the bundler actually emits.
// 0.2.7 shipped exactly this: stock Tauri signatures with no version field, which every
// installed 0.2.6 refused under requireSignedVersion. It must now block the release instead.
test('a signature that does not record the release version blocks publication', t => {
  const { source, output, run } = fixture(t);
  for (const name of [...names, ...signedNames]) fs.writeFileSync(path.join(source, name), content(name));
  const stock = Buffer.from('untrusted comment: x\nRUTest\ntrusted comment: timestamp:1\tfile:Tachyon.app.tar.gz\nsig\n').toString('base64');
  fs.writeFileSync(path.join(source, 'Tachyon.app.tar.gz.sig'), stock);
  let result = run(true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not record version:0\.2\.1/);
  assert.ok(!fs.existsSync(path.join(output, 'latest.json')));
  // and a signature for a DIFFERENT version is the replay the field exists to stop
  fs.writeFileSync(path.join(source, 'Tachyon.app.tar.gz.sig'), sigFor('Tachyon.app.tar.gz', '0.2.0'));
  result = run(true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not record version:0\.2\.1/);
});

test('README installer names carry the shipped version', () => {
  const root = new URL('../', import.meta.url);
  const { version } = JSON.parse(fs.readFileSync(new URL('src-tauri/tauri.conf.json', root), 'utf8'));
  const named = fs.readFileSync(new URL('README.md', root), 'utf8').matchAll(/Tachyon_([0-9.]+)_/g);
  const versions = [...new Set([...named].map(m => m[1]))];
  assert.deepEqual(versions, [version]);
});
