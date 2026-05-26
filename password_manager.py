#!/usr/bin/env python3
"""
Password Manager CLI - A secure command-line password manager
Uses AES-256 encryption via Fernet (symmetric) and PBKDF2 key derivation.
"""

import os
import json
import base64
import hashlib
import secrets
import string
import getpass
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependency. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

VAULT_FILE = Path.home() / ".password_vault.json"
ITERATIONS = 480_000  # PBKDF2 iterations (NIST recommended)


# ── Key Derivation ────────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte encryption key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def hash_master_password(master_password: str, salt: bytes) -> str:
    """Hash the master password for verification (separate from encryption key)."""
    dk = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, ITERATIONS)
    return dk.hex()


# ── Vault I/O ─────────────────────────────────────────────────────────────────

def load_vault(path: Path = None) -> dict:
    """Load the vault file from disk."""
    target = path or VAULT_FILE
    if not target.exists():
        return {}
    with open(target, "r") as f:
        return json.load(f)


def save_vault(vault: dict, path: Path = None) -> None:
    """Save the vault to disk."""
    target = path or VAULT_FILE
    with open(target, "w") as f:
        json.dump(vault, f, indent=2)
    target.chmod(0o600)  # Owner read/write only


# ── Authentication ────────────────────────────────────────────────────────────

def setup_master_password(vault_path: Path = None) -> str:
    """First-time setup: create master password and initialize vault."""
    print("\n🔐 First time setup — create your master password.")
    while True:
        pw = getpass.getpass("  New master password: ")
        if len(pw) < 8:
            print("  ✗ Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("  Confirm master password: ")
        if pw != confirm:
            print("  ✗ Passwords do not match. Try again.")
            continue
        break

    salt = os.urandom(32)
    pw_hash = hash_master_password(pw, salt)

    vault = {
        "_meta": {
            "salt": base64.b64encode(salt).decode(),
            "password_hash": pw_hash,
        },
        "entries": {}
    }
    save_vault(vault, vault_path)
    print("  ✓ Vault created successfully!\n")
    return pw


def authenticate(vault_path: Path = None) -> tuple[str, dict]:
    """Authenticate with the master password. Returns (password, vault)."""
    vault = load_vault(vault_path)

    if not vault:
        master_pw = setup_master_password(vault_path)
        vault = load_vault(vault_path)
        return master_pw, vault

    salt = base64.b64decode(vault["_meta"]["salt"])
    stored_hash = vault["_meta"]["password_hash"]

    attempts = 3
    while attempts > 0:
        pw = getpass.getpass("🔑 Master password: ")
        if hash_master_password(pw, salt) == stored_hash:
            print("  ✓ Authenticated.\n")
            return pw, vault
        attempts -= 1
        print(f"  ✗ Wrong password. {attempts} attempt(s) remaining.")

    print("  ✗ Too many failed attempts. Exiting.")
    sys.exit(1)


# ── Encryption / Decryption ───────────────────────────────────────────────────

def encrypt(plaintext: str, key: bytes) -> str:
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str, key: bytes) -> str:
    return Fernet(key).decrypt(ciphertext.encode()).decode()


# ── Clipboard ─────────────────────────────────────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard. Returns True on success."""
    if not CLIPBOARD_AVAILABLE:
        return False
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False


# ── Password Generator ────────────────────────────────────────────────────────

def generate_password(length: int = 16, symbols: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── CRUD Operations ───────────────────────────────────────────────────────────

def add_entry(vault: dict, key: bytes, vault_path: Path = None) -> None:
    """Add a new credential entry."""
    print("\n── Add Entry ──")
    service = input("  Service / website: ").strip()
    if not service:
        print("  ✗ Service name cannot be empty.")
        return
    if service in vault["entries"]:
        overwrite = input(f"  '{service}' already exists. Overwrite? (y/n): ")
        if overwrite.lower() != "y":
            return

    username = input("  Username / email: ").strip()

    gen = input("  Generate a random password? (y/n): ").strip().lower()
    if gen == "y":
        try:
            length = int(input("  Password length (default 16): ").strip() or "16")
        except ValueError:
            length = 16
        sym = input("  Include symbols? (y/n, default y): ").strip().lower()
        password = generate_password(length, symbols=(sym != "n"))
        print(f"  Generated: {password}")
        if copy_to_clipboard(password):
            print("  📋 Password copied to clipboard!")
    else:
        password = getpass.getpass("  Password: ")

    notes = input("  Notes (optional): ").strip()

    vault["entries"][service] = {
        "username": encrypt(username, key),
        "password": encrypt(password, key),
        "notes": encrypt(notes, key) if notes else "",
    }
    save_vault(vault, vault_path)
    print(f"  ✓ '{service}' saved.\n")


def get_entry(vault: dict, key: bytes) -> None:
    """Retrieve and display a credential entry."""
    print("\n── Get Entry ──")
    if not vault["entries"]:
        print("  Vault is empty.\n")
        return

    service = input("  Service name: ").strip()
    if service not in vault["entries"]:
        # Try partial / case-insensitive match
        matches = [s for s in vault["entries"] if service.lower() in s.lower()]
        if len(matches) == 1:
            service = matches[0]
            print(f"  → Found: '{service}'")
        elif len(matches) > 1:
            print(f"  Multiple matches: {', '.join(matches)}")
            print("  Please be more specific.\n")
            return
        else:
            print(f"  ✗ No entry found for '{service}'.\n")
            return

    entry = vault["entries"][service]
    username = decrypt(entry["username"], key)
    password = decrypt(entry["password"], key)
    notes = decrypt(entry["notes"], key) if entry["notes"] else "—"

    print(f"\n  Service:  {service}")
    print(f"  Username: {username}")
    print(f"  Password: {password}")
    print(f"  Notes:    {notes}")

    if CLIPBOARD_AVAILABLE:
        choice = input("\n  Copy password to clipboard? (y/n): ").strip().lower()
        if choice == "y":
            if copy_to_clipboard(password):
                print("  📋 Password copied to clipboard!")
    print()


def search_entries(vault: dict) -> None:
    """Search entries by service name or username (encrypted usernames are skipped)."""
    print("\n── Search ──")
    if not vault["entries"]:
        print("  Vault is empty.\n")
        return

    query = input("  Search query: ").strip().lower()
    if not query:
        return

    matches = [s for s in vault["entries"] if query in s.lower()]

    if not matches:
        print(f"  No entries matching '{query}'.\n")
        return

    print(f"\n  Found {len(matches)} result(s):")
    for i, service in enumerate(sorted(matches), 1):
        print(f"  {i:>2}. {service}")
    print()


def list_entries(vault: dict) -> None:
    """List all stored services."""
    print("\n── Stored Services ──")
    entries = vault["entries"]
    if not entries:
        print("  Vault is empty.\n")
        return
    for i, service in enumerate(sorted(entries.keys()), 1):
        print(f"  {i:>2}. {service}")
    print()


def delete_entry(vault: dict, vault_path: Path = None) -> None:
    """Delete a credential entry."""
    print("\n── Delete Entry ──")
    service = input("  Service to delete: ").strip()
    if service not in vault["entries"]:
        print(f"  ✗ No entry found for '{service}'.\n")
        return
    confirm = input(f"  Delete '{service}'? This cannot be undone. (y/n): ")
    if confirm.lower() == "y":
        del vault["entries"][service]
        save_vault(vault, vault_path)
        print(f"  ✓ '{service}' deleted.\n")
    else:
        print("  Cancelled.\n")


def change_master_password(vault: dict, old_key: bytes, vault_path: Path = None) -> bytes:
    """Change the master password and re-encrypt all entries."""
    print("\n── Change Master Password ──")
    while True:
        new_pw = getpass.getpass("  New master password: ")
        if len(new_pw) < 8:
            print("  ✗ Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("  Confirm new password: ")
        if new_pw != confirm:
            print("  ✗ Passwords do not match.")
            continue
        break

    new_salt = os.urandom(32)
    new_key = derive_key(new_pw, new_salt)
    new_hash = hash_master_password(new_pw, new_salt)

    # Re-encrypt all entries with the new key
    for service, entry in vault["entries"].items():
        vault["entries"][service] = {
            "username": encrypt(decrypt(entry["username"], old_key), new_key),
            "password": encrypt(decrypt(entry["password"], old_key), new_key),
            "notes": encrypt(decrypt(entry["notes"], old_key), new_key) if entry["notes"] else "",
        }

    vault["_meta"]["salt"] = base64.b64encode(new_salt).decode()
    vault["_meta"]["password_hash"] = new_hash
    save_vault(vault, vault_path)
    print("  ✓ Master password updated and vault re-encrypted.\n")
    return new_key


# ── Main Menu ─────────────────────────────────────────────────────────────────

BANNER = """
╔═══════════════════════════════════════╗
║       🔒  PASSWORD MANAGER CLI        ║
║      Encrypted Credential Vault       ║
╚═══════════════════════════════════════╝"""

MENU = """  [1] Add / Update entry
  [2] Get entry
  [3] Search entries
  [4] List all services
  [5] Delete entry
  [6] Generate password
  [7] Change master password
  [0] Exit
"""


def main():
    print(BANNER)

    if not CLIPBOARD_AVAILABLE:
        print("  ℹ  Tip: install pyperclip for clipboard support  (pip install pyperclip)\n")

    master_pw, vault = authenticate()

    salt = base64.b64decode(vault["_meta"]["salt"])
    key = derive_key(master_pw, salt)

    while True:
        print(MENU, end="")
        choice = input("  → ").strip()

        if choice == "1":
            add_entry(vault, key)
        elif choice == "2":
            get_entry(vault, key)
        elif choice == "3":
            search_entries(vault)
        elif choice == "4":
            list_entries(vault)
        elif choice == "5":
            delete_entry(vault)
        elif choice == "6":
            try:
                length = int(input("\n  Password length (default 16): ").strip() or "16")
            except ValueError:
                length = 16
            sym = input("  Include symbols? (y/n, default y): ").strip().lower()
            pw = generate_password(length, symbols=(sym != "n"))
            print(f"\n  Generated: {pw}")
            if copy_to_clipboard(pw):
                print("  📋 Copied to clipboard!")
            print()
        elif choice == "7":
            key = change_master_password(vault, key)
            vault = load_vault()
        elif choice == "0":
            print("\n  Goodbye! 🔐\n")
            break
        else:
            print("  ✗ Invalid choice.\n")


if __name__ == "__main__":
    main()
