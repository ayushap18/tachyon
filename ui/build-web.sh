#!/bin/sh
# Build the Dioxus web frontend; used by tauri.conf beforeDev/beforeBuild.
#
# dx writes to target/dx/tachyon-ui/{debug,release}/web/public, but tauri.conf's
# frontendDist is a single static path — so we build into the right profile and
# then sync it to ui/dist, which is what Tauri actually bundles. Without this the
# release DMG shipped the debug wasm.
#
# Pass --release for the release profile (beforeBuildCommand does).
set -e
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")"

PROFILE=debug
case "$1" in
  --release) PROFILE=release ;;
esac

if [ "$PROFILE" = release ]; then
  dx build --platform web --release
else
  dx build --platform web
fi

OUT="target/dx/tachyon-ui/$PROFILE/web/public"
[ -d "$OUT" ] || { echo "build-web.sh: expected output at $OUT" >&2; exit 1; }

rm -rf dist
cp -R "$OUT" dist
