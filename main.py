import argparse
import logging
import os
import sys
import json
import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Key names that mark a value as sensitive. A plain value under one of
# these names is the case this tool exists to catch.
SENSITIVE_KEY_PARTS = (
    "password", "passwd", "pwd", "api_key", "apikey", "api-key",
    "secret", "token", "private_key", "private-key", "credential",
    "auth_key", "access_key",
)

WEAK_KEY_PATTERNS = [
    "password",
    "12345",
    "admin",
    "secret",
    "test",
]


def setup_argparse():
    parser = argparse.ArgumentParser(description="Verify encryption of sensitive data in configuration files.")
    parser.add_argument("config_file", help="Path to the configuration file.")
    parser.add_argument(
        "--encryption_key",
        help="Encryption key (if applicable).  If not provided, the tool will attempt to detect common key patterns.",
        required=False,
    )
    parser.add_argument(
        "--file_type",
        help="Specify the file type (yaml or json). If not specified, it will be inferred.",
        choices=['yaml', 'json'],
        required=False
    )
    parser.add_argument(
        "--detect_weak_keys",
        action="store_true",
        help="Enable detection of weak encryption keys or patterns (e.g., 'password', '12345').",
    )
    return parser


def load_config_file(config_file_path, file_type=None):
    if file_type is None:
        _, file_extension = os.path.splitext(config_file_path)
        file_extension = file_extension.lstrip(".").lower()
        if file_extension == "json":
            file_type = "json"
        elif file_extension in ("yaml", "yml"):
            file_type = "yaml"
        else:
            logging.error(f"Unsupported file type: {file_extension}")
            return None
    try:
        with open(config_file_path, "r") as f:
            if file_type == "json":
                return json.load(f)
            elif file_type == "yaml":
                return yaml.safe_load(f)
            else:
                logging.error(f"Unsupported file type: {file_type}")
                return None
    except FileNotFoundError:
        logging.error(f"File not found: {config_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON file: {config_file_path}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error decoding YAML file: {config_file_path}: {e}")
        return None


def is_sensitive_key(path):
    # Only the leaf of the path is tested, and the test is a plain
    # substring search. A key named secretary trips the secret part,
    # and a long key that merely ends in a sensitive word counts the
    # same as one that is exactly that word. Nesting a password
    # under an innocent leaf name hides it from me completely.
    leaf = re.split(r"[.\[\]]", path)[-1] if path else ""
    leaf = leaf.lower()
    return any(part in leaf for part in SENSITIVE_KEY_PARTS)


def is_base64(s):
    """
    Strict base64 check: valid alphabet and padding, canonical form,
    and long enough to be more than a short plain word.
    """
    if not isinstance(s, str) or len(s) < 16 or len(s) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(s, validate=True)
    except Exception:
        return False
    return base64.b64encode(decoded).decode() == s


def classify_value(value, path, encryption_key=None, detect_weak_keys=False):
    """
    Classify one string value. Returns one of:
    verified, encrypted_unverified, possible_encrypted, weak,
    unencrypted_sensitive, none.

    The value itself is never logged here or anywhere else. Callers
    report the key path and this kind only.
    """
    if not isinstance(value, str) or value == "":
        return "none"

    # That prefix is the Fernet token shape, and it is the only
    # encryption format I recognise on sight. A value encrypted
    # some other way and stored as plain base64 gets at best the
    # possible label below, and one stored in hex gets called
    # unencrypted, however strong the scheme behind it was.
    if value.startswith("gAAAAAB"):
        if encryption_key:
            try:
                f = Fernet(encryption_key.encode())
                f.decrypt(value.encode())  # Decrypted bytes are discarded, never logged or written.
                logging.info(f"Encrypted value verified with the provided key at: {path}")
                return "verified"
            # A key in the wrong format raises ValueError from the Fernet
            # constructor rather than InvalidToken, and lands in the broad
            # handler below. Both routes end at the same unverified label,
            # so the log is the only place the distinction survives.
            except InvalidToken:
                # A Fernet shaped value that this key cannot open is
                # still encrypted shaped; report it as encrypted but
                # unverified, not as absent.
                logging.warning(f"Encrypted value at {path} could not be verified with the provided key.")
                return "encrypted_unverified"
            except Exception as e:
                logging.error(f"Error during decryption attempt at {path}: {e}")
                return "encrypted_unverified"
        logging.warning(f"Encrypted value at {path} cannot be verified: no encryption key provided.")
        return "encrypted_unverified"

    if detect_weak_keys:
        value_lower = value.lower()
        for pattern in WEAK_KEY_PATTERNS:
            # These patterns match as substrings, not as whole values, and
            # this check runs on every string in the file when the flag is
            # set, not just under sensitive keys. The word latest contains
            # test, so an ordinary version string can come back as a weak
            # key finding. I keep the patterns blunt because a weak value
            # hiding inside a longer one is also worth surfacing.
            if pattern in value_lower:
                logging.warning(f"Weak pattern detected at: {path}")
                return "weak"

    sensitive = is_sensitive_key(path)

    if is_base64(value):
        if sensitive:
            logging.warning(f"Possible encrypted value (base64 shaped, unverified) at: {path}")
            return "possible_encrypted"
        # A base64 decodable string under an ordinary key name is not
        # called encryption. Plenty of plain values decode as base64.
        return "none"

    if sensitive:
        logging.warning(f"Sensitive value at {path} does not match any encryption shape: reported as unencrypted.")
        return "unencrypted_sensitive"

    return "none"


def detect_encryption(value, encryption_key=None, detect_weak_keys=False):
    """Kept for compatibility: True when a value is encryption shaped."""
    # The empty path here means this wrapper can never see a
    # sensitive key, so the base64 branch inside classify_value
    # returns none for it and possible_encrypted is unreachable
    # through this function. Only the Fernet branch can make it
    # return True. It stays because older callers import the name.
    return classify_value(value, "", encryption_key, detect_weak_keys) in (
        "verified", "encrypted_unverified", "possible_encrypted")


def traverse_config(config_data, encryption_key=None, detect_weak_keys=False, path="", findings=None, stats=None):
    """
    Walk the config and collect findings as (path, kind) pairs.
    Values are never placed in a finding.
    """
    if findings is None:
        findings = []
    if stats is None:
        stats = {"checked": 0}
    if isinstance(config_data, dict):
        for key, value in config_data.items():
            current_path = f"{path}.{key}" if path else str(key)
            traverse_config(value, encryption_key, detect_weak_keys, current_path, findings, stats)
    elif isinstance(config_data, list):
        for i, item in enumerate(config_data):
            current_path = f"{path}[{i}]"
            traverse_config(item, encryption_key, detect_weak_keys, current_path, findings, stats)
    elif isinstance(config_data, str):
        # Only strings are counted, and only strings are classified.
        # A config whose sensitive values are numbers, like a numeric
        # PIN stored as an integer, contributes nothing to this count
        # and nothing to the findings, which is a gap a reader of the
        # summary number alone would never suspect.
        stats["checked"] += 1
        kind = classify_value(config_data, path, encryption_key, detect_weak_keys)
        if kind not in ("none", "verified"):
            findings.append((path, kind))
    return findings, stats


# Kinds that fail the run: a gate must be able to trust the exit code.
FAILING_KINDS = ("unencrypted_sensitive", "encrypted_unverified", "possible_encrypted", "weak")


def main():
    parser = setup_argparse()
    args = parser.parse_args()

    if not os.path.exists(args.config_file):
        logging.error(f"Configuration file not found: {args.config_file}")
        sys.exit(1)

    config_data = load_config_file(args.config_file, args.file_type)
    if config_data is None:
        logging.error("Nothing was checked: the configuration could not be loaded or is empty.")
        sys.exit(1)

    findings, stats = traverse_config(config_data, args.encryption_key, args.detect_weak_keys)

    if stats["checked"] == 0:
        logging.error("Nothing was checked: the configuration holds no string values.")
        sys.exit(1)

    for path, kind in findings:
        logging.warning(f"Finding at {path}: {kind}")

    logging.info("Misconfiguration detection completed.")

    if any(kind in FAILING_KINDS for _, kind in findings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
