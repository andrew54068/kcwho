# Requester verification

Parser regression tests verify interpretation of sanitized events. Live controls independently verify that the report matches the process actually launched.

## Isolated native test protocol

Run in the desktop login session (Aqua). Use a fresh temporary directory and a disposable keychain with a known test-only password, a unique service/account, and dummy data. Record and restore the original user keychain search list if creation changes it. Avoid the login keychain.

For item-access tests, unlock the disposable keychain before starting and keep it unlocked for the test. Create the dummy item with an empty trusted-application list (`security add-generic-password ... -T ''`) so reading it prompts for access. A locked keychain instead tests unlock handling, whose logs can lack caller identity.

Before each case, confirm there is no existing authentication dialog or pending test request. Independently record the exact test executable path and launched PID. Compare those with `waiting[].tool` and `waiting[].pid`, not just the displayed app name.

| Case | Trigger | Required result |
| --- | --- | --- |
| Known process | `/usr/bin/security find-generic-password` for the dummy item in the explicit disposable keychain | The actual `security` PID and `/usr/bin/security`; current signing identified as Apple |
| Unfamiliar process | A separately compiled, uniquely named client calling `SecKeychainFindGenericPassword` for that same dummy item | The actual client PID/path, without a name whitelist or unrelated app substitution |
| Unrelated prompt | An isolated client requesting `system.privilege.admin` through Authorization Services | No Keychain requester inferred from the dialog host or historical iCloud activity |
| Unsupported unlock | Lock the disposable keychain, then request the dummy item | Unknown if no caller PID is published; never a guessed Reminders/Contacts attribution |

Cancel or deny each test. Do not enter real credentials or choose Always Allow. Confirm the request disappears after cancellation. An unresolved native query may remain unknown if its caller exits or logs are incomplete. Stop only owned test processes; do not kill system authentication services. Delete the disposable keychain, unload owned test jobs, remove temporary files, and verify the original search list is preserved.

## Scope of evidence

Tests on one macOS build do not establish compatibility with other versions. System logs establish an active OS-reported immediate requester; they do not bind a query to an individual window or establish the upstream app behind iCloud Helper. Built-in `--snapshot` output is a rendering of the observer's panel, not independent proof of the native dialog's text.

Raw live-test evidence stays local and is excluded from Git. Only sanitized fixtures belong in the public repository.
