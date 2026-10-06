# Contributing to kcwho

Fork the repository and create a focused branch from `main`. Read the [README](README.md), especially the limits of requester attribution, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development

Use macOS with Apple's Command Line Tools. Python uses only its standard library; Swift uses system frameworks. No dependency installation or root access is needed.

```bash
/usr/bin/python3 scripts/test_kcwho.py
/usr/bin/python3 scripts/test_install.py
scripts/install.sh build
bash -n scripts/install.sh
build/kcwatch --kcwho "$PWD/kcwho"
```

The installed LaunchAgent runs copied programs. Reinstall explicitly when testing changes to that instance.

## Changes and pull requests

Describe the concrete trigger, resulting behavior, and checks you actually ran. Add regression coverage when changing attribution or handling incomplete evidence. Preserve the distinction between direct requester, upstream app, diagnostic candidate, and window association. Never introduce a guess presented as a verified requester.

Native tests must use a disposable keychain containing dummy data, preserve the user's original search list, and clean up owned jobs and files. Never ask contributors to approve access to real credentials. Follow the manual protocol in [docs/verification.md](docs/verification.md).

Open pull requests against `main`. Do not commit build output, raw system logs, screenshots with private information, Keychain files, or local agent configuration. Report ordinary problems in [issues](https://github.com/andrew54068/kcwho/issues); report vulnerabilities using [SECURITY.md](SECURITY.md).
