#!/bin/sh
# Build the Dioxus web frontend; used by tauri.conf beforeDev/beforeBuild.
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")" || exit 1
exec dx build --platform web "$@"
