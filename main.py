import argparse
import logging
import os
import json
import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the CLI tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Verify encryption of sensitive data in configuration files.")
    parser.add_argument("config_file", help="Path to the configuration file.")
    parser.add_argument(
        "--encryption_key",
        help="Encryption key (if applicable).  If not provided, the tool will attempt to detect common key patterns.",
        required=False,  # Make encryption_key optional
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
    """
    Loads the configuration file based on its type (JSON or YAML).

    Args:
        config_file_path (str): Path to the configuration file.
        file_type (str, optional): Explicitly specify the file type ("yaml" or "json"). If None, it will attempt to infer the file type from the extension.

    Returns:
        dict: The loaded configuration data as a dictionary.
        None: If the file type is not supported, or if there's an error loading the file.
    """

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
                logging.error(f"Unsupported file type: {file_type}")  # Redundant check but good for clarity
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


def detect_encryption(value, encryption_key=None, detect_weak_keys=False):
    """
    Detects if a value is potentially encrypted using Fernet or a similar method.
    Also detects weak keys if requested.

    Args:
        value (str): The value to check for encryption.
        encryption_key (str, optional): Encryption key to attempt decryption. Defaults to None.
        detect_weak_keys (bool): If True, will perform weak key detection.

    Returns:
        bool: True if encryption is detected (or seems likely), False otherwise.
    """
    if not isinstance(value, str):
        return False

    # Check for Fernet format (base64 encoded with "gAAAAAB" prefix)
    if value.startswith("gAAAAAB"):
        try:
            if encryption_key:  # Try decrypting if key is provided
                f = Fernet(encryption_key.encode())
                f.decrypt(value.encode())  # Test decryption - no actual use of the decrypted value
                logging.info("Possible encrypted value detected and successfully decrypted with the provided key.")
                return True
            else:
                 logging.warning("Possible encrypted value detected but no encryption key provided.  Unable to verify.")
                 return True # Return True so it flags it as potential encryption
        except InvalidToken:
            logging.warning("Possible encrypted value detected, but decryption failed with the provided key (InvalidToken).")
            return False
        except Exception as e:
            logging.error(f"Error during decryption attempt: {e}")
            return False

    # Check for base64 encoded strings, which is a common encryption output
    if is_base64(value):
        logging.warning("Possible Base64 encoded value detected.  It MAY be encrypted, but this is not guaranteed.")
        return True # Treat as potential encryption to encourage manual review

    #Weak Key Detection (OPTIONAL)
    if detect_weak_keys:
        weak_key_patterns = [
            "password",
            "12345",
            "admin",
            "secret",
            "test"
        ]

        value_lower = value.lower()  # Case-insensitive matching
        for pattern in weak_key_patterns:
            if pattern in value_lower:
                logging.warning(f"Possible use of weak key pattern '{pattern}' detected in value: {value}")
                return True  # Flag it, as it might contain a weak key or related information.

    return False


def is_base64(s):
    """
    Checks if a string is likely base64 encoded.
    """
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False


def traverse_config(config_data, encryption_key=None, detect_weak_keys=False, path=""):
    """
    Recursively traverses the configuration data to detect potentially encrypted values.

    Args:
        config_data (dict or list): The configuration data to traverse.
        encryption_key (str, optional): Encryption key to attempt decryption. Defaults to None.
        detect_weak_keys (bool): If True, will perform weak key detection.
        path (str): The current path in the configuration (for logging).
    """

    if isinstance(config_data, dict):
        for key, value in config_data.items():
            current_path = f"{path}.{key}" if path else key
            traverse_config(value, encryption_key, detect_weak_keys, current_path)  # Recursive call
    elif isinstance(config_data, list):
        for i, item in enumerate(config_data):
            current_path = f"{path}[{i}]"
            traverse_config(item, encryption_key, detect_weak_keys, current_path)  # Recursive call
    elif isinstance(config_data, str):
        if detect_encryption(config_data, encryption_key, detect_weak_keys):
            logging.warning(f"Possible encrypted value detected at: {path} = {config_data}")
    else:
        pass # Ignore non-string/list/dict values


def main():
    """
    Main function to execute the misconfiguration detection tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not os.path.exists(args.config_file):
        logging.error(f"Configuration file not found: {args.config_file}")
        return

    config_data = load_config_file(args.config_file, args.file_type)
    if config_data is None:
        return

    traverse_config(config_data, args.encryption_key, args.detect_weak_keys)

    logging.info("Misconfiguration detection completed.")

if __name__ == "__main__":
    main()