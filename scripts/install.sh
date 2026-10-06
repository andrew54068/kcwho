#!/usr/bin/env bash
# Runs kcwatch at every login: whenever a password popup appears, a heads-up
# naming who is behind it shows up right beside it.
#
# The agent runs installed copies of kcwatch and kcwho, not the files here.
# Re-run `install` after editing kcwho or kcwatch.swift.
set -euo pipefail

PLIST_LABEL="com.dawson.kcwatch"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
BUILT="$PROJECT_DIR/build/kcwatch"
# TCC: launchd may not read files under ~/Documents ("Operation not
# permitted", exit 126). Install to a non-TCC path and log to ~/Library/Logs.
INSTALL_DIR="$HOME/Library/Application Support/$PLIST_LABEL"
# The installed program's FILENAME is what the macOS "Login Items & Extensions
# → Allow in the Background" panel shows for a bare launchd agent. kcwatch
# runs the kcwho installed next to it.
PROGRAM_NAME="Keychain Popup Watch"
INSTALLED_PROGRAM="$INSTALL_DIR/$PROGRAM_NAME"
LOG_FILE="$HOME/Library/Logs/kcwatch.log"
DOMAIN="gui/$(id -u)"

usage() {
  cat <<'USAGE'
Usage: scripts/install.sh <build|install|uninstall|status>

  build      compile kcwatch.swift into build/kcwatch
  install    build, install kcwatch + kcwho, start now and at every login
  uninstall  stop it, remove the LaunchAgent and the installed copies
  status     is it running? plus the last log lines
USAGE
  exit 1
}

[ "$#" -eq 1 ] || usage
command -v launchctl >/dev/null 2>&1 || { echo "ERROR: launchctl not available"; exit 1; }

build() {
  command -v swiftc >/dev/null 2>&1 || { echo "ERROR: swiftc not found (run: xcode-select --install)"; exit 1; }
  mkdir -p "$PROJECT_DIR/build"
  swiftc -O -swift-version 5 -o "$BUILT" "$PROJECT_DIR/kcwatch.swift"
  echo "Built: $BUILT"
}

install_agent() {
  build
  mkdir -p "$HOME/Library/LaunchAgents" "$INSTALL_DIR" "$(dirname "$LOG_FILE")"
  install -m 755 "$BUILT" "$INSTALLED_PROGRAM"
  install -m 755 "$PROJECT_DIR/kcwho" "$INSTALL_DIR/kcwho"
  cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>$PLIST_LABEL</string>
    <key>ProgramArguments</key><array><string>$INSTALLED_PROGRAM</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
    <key>ProcessType</key><string>Interactive</string>
    <key>StandardOutPath</key><string>$LOG_FILE</string>
    <key>StandardErrorPath</key><string>$LOG_FILE</string>
  </dict>
</plist>
EOF
  plutil -lint "$PLIST_PATH" >/dev/null
  launchctl bootout "$DOMAIN/$PLIST_LABEL" >/dev/null 2>&1 || true
  # bootout is asynchronous; bootstrapping before the old job drains fails with EIO (5).
  for _ in 1 2 3 4 5; do launchctl print "$DOMAIN/$PLIST_LABEL" >/dev/null 2>&1 || break; sleep 1; done
  launchctl bootstrap "$DOMAIN" "$PLIST_PATH"
  echo "Installed LaunchAgent ($DOMAIN): $PLIST_LABEL"
  echo "Program (shown in Login Items): $INSTALLED_PROGRAM"
  echo "Log: $LOG_FILE"
}

show_status() {
  launchctl print "$DOMAIN/$PLIST_LABEL" 2>/dev/null \
    | grep -E 'state =|runs =|last exit' | head -3 || echo "not loaded"
  tail -3 "$LOG_FILE" 2>/dev/null || true
}

case "$1" in
  build)     build ;;
  install)   install_agent ;;
  uninstall) launchctl bootout "$DOMAIN/$PLIST_LABEL" >/dev/null 2>&1 || true
             rm -f "$PLIST_PATH"; rm -rf "$INSTALL_DIR"; echo "Uninstalled $PLIST_LABEL" ;;
  status)    show_status ;;
  *)         usage ;;
esac
