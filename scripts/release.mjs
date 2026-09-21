// Collect only complete release sets; never publish a macOS-only release by accident.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const [tag, source, destination] = process.argv.slice(2);
if (!/^v\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(tag ?? '') || !source || !destination) {
  throw new Error('Usage: node scripts/release.mjs vX.Y.Z installers release-assets');
}
const version = tag.slice(1);
const files = fs.readdirSync(source, { recursive: true }).map(file => path.join(source, file));
const required = [
  `Tachyon_${version}_aarch64.dmg`,
  `Tachyon_${version}_amd64.deb`,
  `Tachyon_${version}_amd64.AppImage`,
];
// What the updater downloads, per latest.json platform key. With createUpdaterArtifacts:true
// (not "v1Compatible") the bundler tars the macOS .app but signs the AppImage as-is, so the
// Linux entry IS the human installer and only its .sig is new.
// ponytail: pinned from the bundler's documented v2 output, not yet from a CI log. A wrong
// name fails the publish below with "Expected exactly one", never a half-set.
const updater = {
  'darwin-aarch64': 'Tachyon.app.tar.gz',
  'linux-x86_64': `Tachyon_${version}_amd64.AppImage`,
};
// The workflow says whether CI held the signing key, so a mis-globbed .sig fails loudly
// instead of being mistaken for an unsigned build.
const signed = process.env.UPDATER_SIGNED === 'true';
fs.mkdirSync(destination, { recursive: true });
const checksums = [];
const pick = name => {
  const matches = files.filter(file => path.basename(file) === name && fs.statSync(file).isFile());
  if (matches.length !== 1) throw new Error(`Expected exactly one ${name}, found ${matches.length}`);
  const data = fs.readFileSync(matches[0]);
  if (data.length === 0) throw new Error(`Empty release file: ${name}`);
  fs.copyFileSync(matches[0], path.join(destination, name));
  checksums.push(`${createHash('sha256').update(data).digest('hex')}  ${name}`);
  return data;
};
for (const name of required) pick(name);
if (signed) {
  const platforms = {};
  for (const [key, name] of Object.entries(updater)) {
    if (!required.includes(name)) pick(name);
    const signature = pick(`${name}.sig`).toString('utf8').trim();
    // tauri.conf.json sets requireSignedVersion, so the installed app refuses a signature
    // whose trusted comment lacks `version:<v>` — and no released Tauri CLI writes that field
    // (tools/sign-updater does). 0.2.7 shipped without it and no copy of 0.2.6 could install
    // it. Checked here so that mistake fails the release instead of a user's update.
    const comment = Buffer.from(signature, 'base64').toString('utf8');
    if (!comment.split(/[\t\n]/).includes(`version:${version}`)) {
      throw new Error(`${name}.sig does not record version:${version}; run tools/sign-updater before publishing`);
    }
    platforms[key] = {
      signature,
      // Pinned to the tag: only the manifest itself is fetched through releases/latest.
      url: `https://github.com/ayushap18/tachyon/releases/download/${tag}/${name}`,
    };
  }
  fs.writeFileSync(path.join(destination, 'latest.json'), JSON.stringify({
    version, notes: `Tachyon ${tag}`, pub_date: new Date().toISOString(), platforms,
  }, null, 2) + '\n');
}
fs.writeFileSync(path.join(destination, 'SHA256SUMS'), checksums.join('\n') + '\n');
fs.writeFileSync(path.join(destination, 'RELEASE_NOTES.md'), `Tachyon ${tag}

Installers for all supported platforms are attached:

| Platform | Download | Self-update (Tachyon 0.2.6 and later) |
| --- | --- | --- |
| macOS · Apple Silicon | \`Tachyon_${version}_aarch64.dmg\` | In place: ⌘U, once Tachyon runs from /Applications |
| Linux · x86_64 · Debian/Ubuntu | \`Tachyon_${version}_amd64.deb\` | No: install the new .deb with apt |
| Linux · x86_64 · AppImage | \`Tachyon_${version}_amd64.AppImage\` | In place: Ctrl+U, if the AppImage's folder is writable |
${signed ? '' : `
This release carries no updater manifest (\`latest.json\`), so installed copies of Tachyon will
not be offered it. Download it by hand.
`}
Linux native binaries are built on Ubuntu 22.04. For Debian/Ubuntu, install with
\`sudo apt install ./Tachyon_${version}_amd64.deb\` so dependencies are resolved.
For AppImage, run \`chmod +x Tachyon_${version}_amd64.AppImage\` and launch it.
If FUSE is unavailable, use \`./Tachyon_${version}_amd64.AppImage --appimage-extract-and-run\`.

Builds are not signed by Apple. On macOS, the first install may need System Settings →
Privacy & Security → Open Anyway; an in-place update is downloaded by Tachyon itself, not a
browser, so it is not quarantined and does not ask again. Windows and Linux ARM packages are not available.

Download SHA256SUMS alongside your installer and verify its entry with \`sha256sum --ignore-missing -c SHA256SUMS\`
on Linux, or \`shasum -a 256 <installer>\` on macOS.

See [CHANGELOG.md](https://github.com/ayushap18/tachyon/blob/${tag}/CHANGELOG.md) for changes
and [README.md](https://github.com/ayushap18/tachyon/blob/${tag}/README.md) for setup.
`);
console.log(`Verified ${required.length} installers for ${tag}; wrote SHA256SUMS${signed ? ' and latest.json' : ' (unsigned: no latest.json)'}.`);
