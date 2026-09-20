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
fs.mkdirSync(destination, { recursive: true });
const checksums = [];
for (const name of required) {
  const matches = files.filter(file => path.basename(file) === name && fs.statSync(file).isFile());
  if (matches.length !== 1) throw new Error(`Expected exactly one ${name}, found ${matches.length}`);
  const data = fs.readFileSync(matches[0]);
  if (data.length === 0) throw new Error(`Empty installer: ${name}`);
  fs.copyFileSync(matches[0], path.join(destination, name));
  checksums.push(`${createHash('sha256').update(data).digest('hex')}  ${name}`);
}
fs.writeFileSync(path.join(destination, 'SHA256SUMS'), checksums.join('\n') + '\n');
fs.writeFileSync(path.join(destination, 'RELEASE_NOTES.md'), `Tachyon ${tag}

Installers for all supported platforms are attached:

| Platform | Download |
| --- | --- |
| macOS · Apple Silicon | \`Tachyon_${version}_aarch64.dmg\` |
| Linux · x86_64 · Debian/Ubuntu | \`Tachyon_${version}_amd64.deb\` |
| Linux · x86_64 · AppImage | \`Tachyon_${version}_amd64.AppImage\` |

Linux native binaries are built on Ubuntu 22.04. For Debian/Ubuntu, install with
\`sudo apt install ./Tachyon_${version}_amd64.deb\` so dependencies are resolved.
For AppImage, run \`chmod +x Tachyon_${version}_amd64.AppImage\` and launch it.
If FUSE is unavailable, use \`./Tachyon_${version}_amd64.AppImage --appimage-extract-and-run\`.

Builds are unsigned. On macOS, use System Settings → Privacy & Security → Open Anyway
if Gatekeeper blocks the first launch. Windows and Linux ARM packages are not available.

Download SHA256SUMS alongside your installer and verify its entry with \`sha256sum --ignore-missing -c SHA256SUMS\`
on Linux, or \`shasum -a 256 <installer>\` on macOS.

See [CHANGELOG.md](https://github.com/ayushap18/tachyon/blob/${tag}/CHANGELOG.md) for changes
and [README.md](https://github.com/ayushap18/tachyon/blob/${tag}/README.md) for setup.
`);
console.log(`Verified ${required.length} installers for ${tag}; wrote SHA256SUMS.`);
