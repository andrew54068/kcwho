# kcwho

Read-only diagnostics for macOS Keychain permission requests, with a native panel beside authentication dialogs.

kcwho reports the **direct requester identified by macOS**, its PID, executable path, and current signing status. It does not decide whether a request is safe to approve.

## Build and run

Requirements: macOS, Apple's Command Line Tools (`swiftc`, Python 3), and a logged-in desktop session. The current implementation was tested on macOS 15.7.4 (Apple silicon); other versions are unverified. There are no third-party runtime packages.

```bash
git clone https://github.com/andrew54068/kcwho.git
cd kcwho
scripts/install.sh build
./kcwho
./kcwho --json
```

Run in Terminal on the Mac displaying the dialog. SSH and background sessions may not expose the same windows or Keychain interaction state.

For the panel without installing a login agent:

```bash
build/kcwatch --kcwho "$PWD/kcwho"
```

To run the watcher now and at each desktop login:

```bash
scripts/install.sh install
scripts/install.sh status
# Stop and remove the installed observer:
scripts/install.sh uninstall
```

The installer builds locally, copies the programs to `~/Library/Application Support/com.dawson.kcwatch/`, and registers `~/Library/LaunchAgents/com.dawson.kcwatch.plist`. Status messages go to `~/Library/Logs/kcwatch.log`. Reinstall after changing source; the agent runs its installed copies.

## What the result means

The panel lists active **OS-reported Keychain requests**. Its JSON report uses `kind: "keychain"` when a direct requester can be verified, `"unknown"` when relevant evidence is incomplete or unavailable, and `"none"` when it found no active Keychain query. `none` does not certify that a dialog is harmless or identify what it is asking for.

The requester comes from securityd's explicit `displaying keychain prompt` event. A matching query PID, user, daemon thread, and query construction event establish an OS-reported request. Query destruction removes it. The parser filters the current boot and daemon instance, then checks the live executable and kernel process birth time to reject PID reuse.

Signing describes the **current process identity**, not its intent or the safety of approving access. Diagnostic running-process candidates are separate from requester evidence and contain no command-line arguments.

## Limits

- The system log format is an implementation detail, not a stable public observation API. Missing, redacted, lost, or changed events can make attribution unavailable. Logs may be incomplete without an explicit loss marker.
- Some prompts, including whole-Keychain unlock requests, publish no caller PID and remain unknown.
- An individual CoreGraphics window is **not bound** to a query object. Multiple active requests are listed separately; the panel cannot tell which belongs to a particular window.
- If iCloud Helper is the direct requester, the original app behind it remains unverified. Historical Reminders or Contacts account lookups do not prove ownership of the current request.
- Process identity and request ownership are different facts. A running process, Apple signature, parent process, or launchd job alone is not requester evidence.

kcwho cannot provide universally airtight attribution. Compare the reported evidence with the macOS dialog, and cancel requests whose purpose you do not recognize.

## Privacy

The observer reads window owner/position metadata, selected local system logs, and process identity metadata. It does not read Keychain item contents, collect process arguments or passwords, enter credentials, approve dialogs, or send telemetry. It needs no root privileges, Accessibility permission, or Screen Recording permission.

CLI output and local status logs can contain executable paths, process names, and job labels. Review them before sharing. Do not upload raw system logs, Keychain files, or screenshots containing private information.

## Verify and contribute

```bash
/usr/bin/python3 scripts/test_kcwho.py
scripts/install.sh build
bash -n scripts/install.sh
```

The regression fixtures are sanitized examples of captured securityd message shapes. They test stale helper activity, unrelated prompts, unknown clients, query lifetime, multiple requests, PID reuse, source/boot checks, missing evidence, and argument privacy. They do not replace live native-dialog testing. See [docs/verification.md](docs/verification.md) for the manual protocol and tested limits.

Report ordinary bugs or questions through [GitHub issues](https://github.com/andrew54068/kcwho/issues). For vulnerabilities, see [SECURITY.md](SECURITY.md). Development guidance is in [CONTRIBUTING.md](CONTRIBUTING.md); participants follow the [Code of Conduct](CODE_OF_CONDUCT.md).
