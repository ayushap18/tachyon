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
function fixture(t, tag = 'v0.2.1') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tachyon-release-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'installers');
  const output = path.join(root, 'release-assets');
  fs.mkdirSync(source);
  const run = (signed = false) => spawnSync(process.execPath, [new URL('./release.mjs', import.meta.url).pathname, tag, source, output],
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

// The beta channel is a tag shape, not a code path: the bundler interpolates tauri.conf.json's
// version verbatim into `<productName>_<version>_<arch>`, so the prerelease suffix travels into
// every installer name, checksum and updater URL. release.mjs's `required` list is written
// against that template, so it holds for a beta only if nothing here truncates at the hyphen.
test('a prerelease tag keeps its suffix in every filename and updater url', t => {
  const version = '0.3.0-beta.0';
  const beta = names.map(name => name.replace('0.2.1', version));
  // Tachyon.app.tar.gz carries no version: the macOS updater tarball is the same name on
  // every channel, and only latest.json's url pins it to the tag.
  const betaSigned = signedNames.map(name => name.replace('0.2.1', version));
  const { source, output, run } = fixture(t, `v${version}`);
  for (const name of [...beta, ...betaSigned]) {
    fs.writeFileSync(path.join(source, name), name.endsWith('.sig') ? sigFor(name.slice(0, -4), version) : `file ${name}\n`);
  }
  const result = run(true);
  assert.equal(result.status, 0, result.stderr);
  const checksums = fs.readFileSync(path.join(output, 'SHA256SUMS'), 'utf8').trim().split('\n');
  assert.deepEqual(checksums.map(line => line.split('  ')[1]).sort(), [...beta, ...betaSigned].sort());
  const latest = JSON.parse(fs.readFileSync(path.join(output, 'latest.json'), 'utf8'));
  assert.equal(latest.version, version);
  assert.equal(latest.platforms['linux-x86_64'].url,
    `https://github.com/ayushap18/tachyon/releases/download/v${version}/Tachyon_${version}_amd64.AppImage`);
  assert.equal(latest.platforms['darwin-aarch64'].url,
    `https://github.com/ayushap18/tachyon/releases/download/v${version}/Tachyon.app.tar.gz`);
  assert.match(fs.readFileSync(path.join(output, 'RELEASE_NOTES.md'), 'utf8'), /blob\/v0\.3\.0-beta\.0\/CHANGELOG/);
});

// tauri.conf.json's updater endpoint is releases/latest/download/latest.json, and GitHub never
// resolves that to a prerelease. So "not --latest" is the whole thing standing between a beta
// and every installed stable copy, and it is one shell line in release.yml. Pinned here because
// nothing else fails if that line loses its guard.
test('release.yml marks a hyphenated tag prerelease and never latest', () => {
  const root = new URL('../', import.meta.url);
  const yml = fs.readFileSync(new URL('.github/workflows/release.yml', root), 'utf8');
  assert.match(yml, /grep -q -- '-'; then\n\s*gh release edit "\$RELEASE_TAG" --prerelease\n/);
  assert.match(yml, /&& ! echo "\$RELEASE_TAG" \| grep -q -- '-'; then\n\s*gh release edit "\$RELEASE_TAG" --latest\n/);
  assert.equal(yml.match(/--latest/g).length, 1, '--latest must appear only under the no-hyphen guard');
  // The tag gate is written twice — release.yml rejects a bad tag before any build, release.mjs
  // before any asset is copied. Drift is how a shape passes one and fails the other mid-release.
  const mjs = fs.readFileSync(new URL('scripts/release.mjs', root), 'utf8');
  const gate = /\/\^v[^\n]*?\/(?=\.test\()/;
  assert.equal(yml.match(gate)?.[0], mjs.match(gate)?.[0]);
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
  // minisign does not cover the untrusted comment, so a version: field there proves nothing
  // and must not satisfy the check — the plugin reads the trusted line only.
  const untrusted = Buffer.from(
    'untrusted comment: x\tversion:0.2.1\nRUTest\ntrusted comment: timestamp:1\tfile:Tachyon.app.tar.gz\nsig\n',
  ).toString('base64');
  fs.writeFileSync(path.join(source, 'Tachyon.app.tar.gz.sig'), untrusted);
  result = run(true);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not record version:0\.2\.1/);
});

// `[0-9.]+` stopped at the hyphen, so on a prerelease version it captured nothing at all and
// this test failed with an empty list however the README was written — it could not be
// satisfied by a beta. The suffix is part of the filename, so it is part of the capture.
const NAMED_IN_README = /Tachyon_(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)_/g;

test('README installer names carry the shipped version', () => {
  const root = new URL('../', import.meta.url);
  const { version } = JSON.parse(fs.readFileSync(new URL('src-tauri/tauri.conf.json', root), 'utf8'));
  const named = fs.readFileSync(new URL('README.md', root), 'utf8').matchAll(NAMED_IN_README);
  const versions = [...new Set([...named].map(m => m[1]))];
  assert.deepEqual(versions, [version]);
  assert.deepEqual([...'Tachyon_0.3.0-beta.0_amd64.deb'.matchAll(NAMED_IN_README)].map(m => m[1]), ['0.3.0-beta.0']);
});
