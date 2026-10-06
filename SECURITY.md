# Security policy

The current `main` branch is the maintained development version. There are no tagged stable releases yet.

## Private reports

Use [GitHub's private vulnerability report form](https://github.com/andrew54068/kcwho/security/advisories/new), or contact the maintainer at **andrew0424718012@gmail.com**. Do not publish exploitable vulnerabilities in public issues.

Include the affected commit, macOS version, reproduction steps, impact, and a sanitized example if available. Do not send passwords, Keychain files, raw system logs, or account identifiers. The maintainer will investigate reports as availability permits; no response-time guarantee is made.

## Security boundary

kcwho is a read-only diagnostic observer. It does not authorize access, suppress system dialogs, or guarantee that a requester is safe. Its current evidence source is best-effort securityd logging. Unknown evidence and unverified upstream callers must remain explicit; see the [README limits](README.md#limits).
