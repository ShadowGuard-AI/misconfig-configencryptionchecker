![Banner](banner.png)

# misconfig-ConfigEncryptionChecker
A CLI tool that verifies if sensitive data within configuration files (e.g., passwords, API keys) are encrypted using a secure method. Uses the `cryptography` library to detect encryption and assess its strength. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

Values are never printed. Findings name the key path and the kind of problem only. A value under a sensitive key name (password, api_key, secret, token, and similar) that matches no encryption shape is reported as unencrypted. A Fernet shaped value that the supplied key cannot open is reported as encrypted but unverified, not passed over. Weak pattern matches are reported under their own label, not as encrypted values.

Exit codes: 1 when a sensitive value is found unencrypted, unverified, or weak, and 1 when nothing was checked (missing file, parse failure, unsupported type, or empty config). 0 only when every checked value is clean or verified with the supplied key.

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configencryptionchecker`

## Usage
`./misconfig-configencryptionchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `--encryption_key`: No description provided
- `--file_type`: No description provided
- `--detect_weak_keys`: Enable detection of weak encryption keys or patterns (e.g., 

## License
Copyright (c) ShadowStrikeHQ
